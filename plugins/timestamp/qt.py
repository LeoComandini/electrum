from PyQt5.QtGui import *
from electrum.plugins import BasePlugin, hook
from electrum.i18n import _
from PyQt5.QtWidgets import (QHBoxLayout, QVBoxLayout, QGridLayout, QPushButton, QLabel, QLineEdit, QFileDialog)
from electrum_gui.qt import EnterButton
from electrum_gui.qt.util import ThreadedButton, Buttons
from electrum_gui.qt.util import WindowModalDialog, OkButton, CloseButton, HelpButton, QRadioButton
from electrum_gui.qt.transaction_dialog import show_transaction
from electrum_gui.qt.main_window import StatusBarButton

from bitcoin.core import *
from opentimestamps.core.timestamp import *
from opentimestamps.core.serialize import BytesSerializationContext, BytesDeserializationContext
from opentimestamps.core.notary import UnknownAttestation, BitcoinBlockHeaderAttestation
from opentimestamps.timestamp import *

from functools import partial
import requests
import json
import base64
import hashlib

from electrum.util import bh2u
from electrum.bitcoin import public_key_from_private_key, regenerate_key, MySigningKey
from ecdsa.curves import SECP256k1
from ecdsa.rfc6979 import generate_k
from ecdsa.util import sigencode_der, sigdecode_der

# PB1:
# what if the signature is in the witness? (e.g. in s2c)
# Electrum servers cannot be asked for the witness path,
# someone else (running a full node) should be asked

# PB2:
# should the case in which the tx is malleated bya 3rd part be managed?

# FIXME: what if I want to timestamp raw data instead of a file? should I add a "Data" class?


# ____ util _________________________________________________________________________


def proof_from_txid_to_block(txid, height, network):
    merkle_path = network.synchronous_get(('blockchain.transaction.get_merkle', [txid, height]))
    timestamp = Timestamp(lx(txid))
    pos = merkle_path["pos"]
    t_old = t_new = timestamp
    for c in merkle_path["merkle"]:
        t_new = cat_sha256d(t_old, Timestamp(lx(c))) if pos % 2 == 0 else cat_sha256d(Timestamp(lx(c)), t_old)
        pos //= 2
        t_old = t_new
    t_new.attestations.add(BitcoinBlockHeaderAttestation(height))
    return timestamp


def roll_timestamp(t):
    # REM: if there is one or more ops then this function rolls into the first one
    try:
        return roll_timestamp(sorted(t.ops.items())[0][1])
    except IndexError:
        return t


def pre_serialize(t):
    """Add an UnknownAttestation if the final timestamp has not one"""

    ft = roll_timestamp(t)
    if len(ft.attestations) == 0:
        ft.attestations.add(UnknownAttestation(b'incompl.', b''))


def post_deserialize(t):
    """Erase UnknownAttestation(s) after deserialization"""

    ft = roll_timestamp(t)
    fa = ft.attestations.copy()
    for a in fa:
        if isinstance(a, UnknownAttestation):
            ft.attestations.remove(a)


def bytes_to_b64string(b):
    return base64.b64encode(b).decode('utf-8')


def b64string_to_bytes(s):
    return base64.b64decode(s.encode('utf-8'))


def safe_hex(b):
    return None if b is None else b2x(b)


def safe_fromhex(h):
    return None if h is None else x(h)


# ____ data containers ______________________________________________________________


class FileData:

    def __init__(self):
        self.path = None
        self.status = None  # tracked, aggregated, pending, completed
        self.mtt = None
        self.txid = None
        self.block = None
        self.detached_timestamp = None

    def from_file(self, path):
        # what should happen if the file does not exists
        self.path = path
        self.status = "tracked"
        self.mtt = None
        self.txid = None
        self.block = None
        with open(self.path, "rb") as fo:
            self.detached_timestamp = DetachedTimestampFile.from_fd(OpSHA256(), fo)

    def from_db(self, d):
        self.path = d["path"]
        self.status = d["status"]
        self.mtt = safe_fromhex(d["mtt"])
        self.txid = d["txid"]
        self.block = d["block"]
        self.detached_timestamp = DetachedTimestampFile.deserialize(BytesDeserializationContext(b64string_to_bytes(d["detached_timestamp"])))
        post_deserialize(self.detached_timestamp.timestamp)

    def as_dict(self):
        d = dict()
        d["path"] = self.path
        d["status"] = self.status
        d["mtt"] = safe_hex(self.mtt)
        d["txid"] = self.txid
        d["block"] = self.block
        pre_serialize(self.detached_timestamp.timestamp)
        ctx = BytesSerializationContext()
        self.detached_timestamp.serialize(ctx)
        d["detached_timestamp"] = bytes_to_b64string(ctx.getbytes())
        # clean the timestamp after the serialization
        ft = roll_timestamp(self.detached_timestamp.timestamp)
        ft.attestations = set()
        return d

    def write_ots(self):
        assert self.status == "complete"
        assert self.block == sorted(roll_timestamp(self.detached_timestamp.timestamp).attestations)[0].height
        ctx = BytesSerializationContext()
        self.detached_timestamp.serialize(ctx)
        with open(self.path + ".ots", "wb") as fw:
            fw.write(ctx.getbytes())


class CalendarData:

    def __init__(self, link=None):
        self.link = link
        self.status = None  # aggregated, broadcasted  # FIXME: is this useful?
        self.tip = None
        self.mtt = None
        self.timestamp = None

    def ask_tip(self):
        """ask calendar tip"""
        self.tip = requests.get(self.link).content
        # manage ConnectionError, what to do in case the link is incorrect?
        if isinstance(self.tip, bytes) and len(self.tip) == 32:
            self.timestamp = Timestamp(self.tip)
        else:
            self.tip = bytes.fromhex("0" * 64)
            self.timestamp = Timestamp(self.tip)
            # raise ValueError("Unexpected data from the calendar")

    def send_to_calendar(self):
        # create ots, send ots to calendar
        # FIXME: actually do it
        print("Sending to calendar", self.link, "[to implement]")
        print("Timestamp: ", self.tip.hex())
        print(self.timestamp.str_tree(verbosity=1))

    def from_db(self, d):  # d = {"link": ..., "mtt": ...}
        self.link = d["link"]
        self.status = "aggregated"  # if the status in the db, then it is aggregated
        self.tip = safe_fromhex(d["tip"])
        self.mtt = safe_fromhex(d["mtt"])
        if d["timestamp"] is None:  # FIXME: may the timestamp ever be None?
            self.timestamp = None
        else:
            self.timestamp = Timestamp.deserialize(BytesDeserializationContext(b64string_to_bytes(d["timestamp"])),
                                                   self.tip)
        post_deserialize(self.timestamp)

    def as_dict(self):
        d = dict()
        d["link"] = self.link
        d["tip"] = safe_hex(self.tip)
        d["mtt"] = safe_hex(self.mtt)
        if self.timestamp is None:  # FIXME: may the timestamp ever be None?
            d["timestamp"] = None
        else:
            pre_serialize(self.timestamp)
            ctx = BytesSerializationContext()
            self.timestamp.serialize(ctx)
            timestamp_serialized = ctx.getbytes()
            d["timestamp"] = bytes_to_b64string(timestamp_serialized)
            # clean the timestamp after the serialization
            ft = roll_timestamp(self.timestamp)
            ft.attestations = set()
        return d

    """
    # what should be sent to the calendar?
    def write_ots(self):
        if self.status == "aggregated":
            extension = ".ots.cal.inc"
        elif self.status == "broadcasted":
            extension = ".ots.cal"
        else:
            return
        ctx = BytesSerializationContext()
        self.timestamp.serialize(ctx)
        file_serialized = ctx.getbytes()
        fw = open(self.path + extension, "wb")
        fw.write(file_serialized)
    """


class ProofsStorage:
    """Container for complete and incomplete proofs"""

    def __init__(self, json_path, element):
        self.json_path = json_path
        self.db = []  # list of dicts
        self.incomplete_proofs = []  # list of FileData/CalendarData
        # FIXME: should element be an attribute?
        self.read_json(element)

    def read_json(self, element):
        """Retrieve data from previous proofs

        read json write on db,
        db -> .ots -> (re)create previous incomplete proofs
        """

        try:
            with open(self.json_path, "r") as f:
                self.incomplete_proofs = []
                self.db = []
                self.db = json.load(f)
                # db -> incomplete_proofs
                if element == "file":
                    for d in self.db:
                        if d["status"] != "complete":
                            f = FileData()
                            f.from_db(d)
                            self.incomplete_proofs += [f]
                if element == "calendar":
                    for d in self.db:
                        c = CalendarData()
                        c.from_db(d)
                        self.incomplete_proofs += [c]
        except FileNotFoundError:
            pass  # the json will be created later

        """
        try:
            with open(self.json_path, "r") as f:
                self.db = json.load(f)
                # db, ots -> incomplete_proofs
                for d in self.db:
                    if inside == "file":
                        if d["status"] != "complete":  # read only incomplete proofs
                            f = FileData()
                            f.from_db(d)
                            self.incomplete_proofs += [f]
                    else:  # assuming calendar
                        c = CalendarData()
                        c.from_db(d)
                        self.incomplete_proofs += [c]
        except FileNotFoundError:  # In case there is no such file it will be written later
            pass
        """

    def write_json(self):
        with open(self.json_path, 'w') as f:
            json.dump(self.db, f)

    def update_db(self):
        try:  # non empty list of files
            db_complete = [d for d in self.db if d["status"] == "complete"]
            self.db = db_complete
        except KeyError:  # list of calendars or empty list
            self.db = []
        for i in self.incomplete_proofs:
            self.db += [i.as_dict()]

    def add_proof(self, proof):
        # FIXME: when this should be called? what should this prevent?
        # assuming that the proof has the same type as the previous and it is not a duplicate or conflictous
        self.incomplete_proofs += [proof]
        self.db += [proof.as_dict()]
        # when adding a calendar proof erase all proofs with the same link
        # when adding a file what should be done?


standard_calendars = ["https://testnet.calendar.eternitywall.com/tip"]
json_path_file = "db_file.json"
json_path_calendar = "db_calendar.json"
default_blocks_until_confirmed = 0  # set to 0 for faster testing, should be 6


class Plugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.proofs_storage_file = ProofsStorage(json_path_file, "file")
        self.proofs_storage_calendar = ProofsStorage(json_path_calendar, "calendar")

        self.extra_calendars = []

    # undergoing functions

    def collect_tips(self):
        """Collect tips from calendars

        previous calendar incomplete proofs will be deleted
        """

        self.proofs_storage_calendar.incomplete_proofs = []
        for link in standard_calendars + self.extra_calendars:
            print("asking tip to", link)
            c = CalendarData(link)
            c.ask_tip()  # which errors could occur?
            self.proofs_storage_calendar.incomplete_proofs += [c]
        self.proofs_storage_calendar.update_db()

    def add_new_file(self, path):
        """start tracking a file for future timestamping"""

        f = FileData()
        f.from_file(path)
        self.proofs_storage_file.add_proof(f)

    def add_new_calendar(self, link):
        """add an extra calendar"""
        # FIXME: check if the calendar is working

        if link in standard_calendars:
            return False
        else:
            self.extra_calendars += [link]
            return True

    def aggregate_timestamps(self):
        """aggregate data to timestamp"""

        self.collect_tips()
        calendar_timestamps = []
        for c in self.proofs_storage_calendar.incomplete_proofs:
            if c.timestamp is not None:  # should this ever happen?
                c.status = "aggregated"
                calendar_timestamps += [nonce_timestamp(c.timestamp)]
        file_timestamps = []
        for f in self.proofs_storage_file.incomplete_proofs:
            f.from_file(f.path)  # overwrite the previous detached timestamps
            f.status = "aggregated"
            file_timestamps += [nonce_timestamp(f.detached_timestamp.timestamp)]
        # how should things be merklelized?
        if file_timestamps + calendar_timestamps == []:
            raise ValueError("Nothing to timestamp")
        else:
            t = make_merkle_tree(file_timestamps + calendar_timestamps)
            # set mtt  # FIXME: is this really necessary?
            for c in self.proofs_storage_calendar.incomplete_proofs:
                if c.status == "aggregated":
                    c.mtt = roll_timestamp(c.timestamp).msg
            for f in self.proofs_storage_file.incomplete_proofs:
                if f.status == "aggregated":
                    f.mtt = roll_timestamp(f.detached_timestamp.timestamp).msg
            self.update_storage(clean_memory=False)
        return t

    def upgrade_timestamps_txid(self, tx):
        """Upgrade the timestamp until txid, send calendars their incomplete proofs"""
        # FIXME: only op_return, extend to s2c

        # To timestamp more files a merkle tree is used and the final timestamp will be common to both.
        # When updating the final timestamp, both the original ones are simultaneously update.
        # But if the proofs are read from the db they are seen as independent timestamps:
        # hence when updating one the timestamp the other does not change.
        # To address this problem before each upgrade (txid, block) the timestamps are read from the db so that the
        # common structure is lost.
        self.proofs_storage_file.read_json("file")
        self.proofs_storage_calendar.read_json(("calendar"))

        for out in tx.outputs():
            if out[0] == 2:
                # mtt -> txid
                mtt = out[1][4:]  # drop "6a20" op_return and op_pushdata(32)
                i = tx.raw.find(mtt)
                prepend = x(tx.raw[:i])
                append = x(tx.raw[i + len(mtt):])
                t_mtt = Timestamp(x(mtt))
                t = t_mtt.ops.add(OpPrepend(prepend))
                t = t.ops.add(OpAppend(append))
                t = t.ops.add(OpSHA256())
                t = t.ops.add(OpSHA256())  # txid in little endian
                # merge the timestamps
                for f in self.proofs_storage_file.incomplete_proofs:
                    tf = roll_timestamp(f.detached_timestamp.timestamp)
                    if tf.msg == x(mtt):
                        tf.merge(t_mtt)  # timestamp upgraded
                        f.status = "pending"
                        f.txid = t.msg[::-1].hex()
                for c in self.proofs_storage_calendar.incomplete_proofs:
                    tc = roll_timestamp(c.timestamp)
                    if tc.msg == x(mtt):
                        tc.merge(t_mtt)  # timestamp upgraded
                        c.status = "broadcasted"
                        c.send_to_calendar()
                # delete the proof sent to calendar
                temp = self.proofs_storage_calendar.incomplete_proofs
                self.proofs_storage_calendar.incomplete_proofs = [p for p in temp if p.status != "broadcasted"]
        self.update_storage(clean_memory=True)

    def upgrade_timestamps_block(self, wallet, network):  # pass the param in this way?
        """upgrade the timestamp until block"""
        # should these be the argument for this function?
        # self -> pending txid
        # wallet -> verified_tx -> height
        # network -> merkle_path
        #         -> local height

        self.proofs_storage_file.read_json("file")
        self.proofs_storage_calendar.read_json(("calendar"))

        local_height = network.get_local_height()
        txid_pending = set([f.txid for f in self.proofs_storage_file.incomplete_proofs if f.status == "pending"])
        for txid in txid_pending:
            try:
                tx_height = wallet.verified_tx[txid][0]
                is_upgradable = (local_height - tx_height >= default_blocks_until_confirmed)
            except KeyError:  # FIXME: check that this is the right error
                is_upgradable = False
            if is_upgradable:
                # txid -> block
                t = proof_from_txid_to_block(txid, tx_height, network)
                for f in self.proofs_storage_file.incomplete_proofs:
                    tf = roll_timestamp(f.detached_timestamp.timestamp)
                    if tf.msg == t.msg:
                        tf.merge(t)
                        f.status = "complete"
                        f.block = tx_height
                        f.write_ots()
                        # f.detached_timestamp = None
        self.update_storage(clean_memory=True)

    def update_storage(self, clean_memory=False):
        self.proofs_storage_file.update_db()
        self.proofs_storage_calendar.update_db()

        self.proofs_storage_file.write_json()
        self.proofs_storage_calendar.write_json()

        if clean_memory:  # timestamps are read from the json so they loose their common dependences
            self.proofs_storage_file.read_json("file")
            self.proofs_storage_calendar.read_json("calendar")

    def timestamp_op_return(self, tx):
        """Aggregate timestamps and insert them in an op_return output

        amounts won't be modified, hence the fee may result inappropriate
        """

        commit = self.aggregate_timestamps().msg
        script = bytes.fromhex("6a") + len(commit).to_bytes(1, "big") + commit
        tx.add_outputs([(2, script.hex(), 0)])

    def sign_to_contract(self, tx, wallet, commit_s2c):
        """Sign a transaction including a commitment in the signature

        Only one signature needs to contain the commitment, the 1st signature of the 1st output will be chosen
        (j=0, i=0); The other inputs are signed in the standard way

        To avoid extra complications the signing phase adhere to the standard signing procedure, still the signature
        containing the commitment point include some unavoidable extra steps

        While the pivot point *must* be stored in this phase, (ephemeral pubkey x, append, prepend) are returned just to
        make things easier
        """

        # FIXME: this should happen in separate thread, as the standard signatures are made.
        # I postpone this since I am not very practical with this things
        password = ""  # should be passed by the function

        # extract the data corresponding to the 1st input (i=0) and its 1st signature (j=0)
        i = 0  # selecting the first input is a lazy choice, is there a better criterion?
        txin_s2c = tx.inputs()[i]
        keystore = wallet.keystore
        keystore.check_password(password)  # decode the xprv
        keypairs = keystore.get_tx_derivations(tx)  # keypairs are the keys corresponding to the inputs of the txl
        for k, v in keypairs.items():
            keypairs[k] = keystore.get_private_key(v, password)  # FIXME: picking all the private key is a lazy solution
        pubkeys, x_pubkeys = tx.get_sorted_pubkeys(txin_s2c)
        j = 0  # the tx input may contain more than 1 pubkey, the 1st is chosen
        x_pubkey = x_pubkeys[j]
        sec, compressed = keypairs.get(x_pubkey)
        pubkey = public_key_from_private_key(sec, compressed)
        pkey = regenerate_key(sec)
        secexp = pkey.secret
        private_key = MySigningKey.from_secret_exponent(secexp, curve=SECP256k1)
        public_key = private_key.get_verifying_key()
        pre_hash = Hash(bytes.fromhex(tx.serialize_preimage(i)))  # what this "i" means?

        # expanded signing phase to include the secp256k1 commitment
        k = generate_k(order=private_key.curve.generator.order(), secexp=secexp, hash_func=hashlib.sha256,
                       data=pre_hash)
        pivot_pt = k * SECP256k1.generator
        pivot_pt_encoded = bytearray(pivot_pt.x().to_bytes(33, "big"))
        pivot_pt_encoded[0] = 2 if pivot_pt.y() % 2 == 0 else 3
        hasher = hashlib.sha256()
        hasher.update(pivot_pt_encoded)
        hasher.update(commit_s2c)
        tweak = int.from_bytes(hasher.digest(), "big")  # tweak = h(pivot||commit_s2c)
        k_tweaked = (k + tweak) % SECP256k1.order  # should some checks be performed?
        sig = private_key.sign_digest(pre_hash, sigencode=sigencode_der, k=k_tweaked)
        # PB: what should be the dimension of ephemeral pubkey?
        # apoelstra return a 32 bytes key but it could be eventually smaller due to DER encoding.
        # for now I assume that what is returned by OpSecp256k1Commitment uses the minimum amount of bytes required.
        # if in the future the byte size of first part of the signature will be fixed (e.g. Schnorr with 32 bytes)
        # prepend will simply include some more b'\x00'
        ephemeral_pubkey_x = sig[4:(4 + sig[3])]
        while ephemeral_pubkey_x[0] == 0:
            ephemeral_pubkey_x = ephemeral_pubkey_x[1:]
        assert ephemeral_pubkey_x == (k_tweaked * SECP256k1.generator).x().to_bytes(32, "big")
        # FIXME: 1 time out of 256 the RHS is < 32 bytes hence the preious fails

        # conclude the signature in the standard way
        assert public_key.verify_digest(sig, pre_hash, sigdecode=sigdecode_der)
        txin_s2c['signatures'][j] = bh2u(sig) + '01'
        txin_s2c['pubkeys'][j] = pubkey  # needed for fd keys # ?
        tx._inputs[i] = txin_s2c
        tx.raw = tx.serialize()

        # sign normally the other inputs
        wallet.sign_transaction(tx, password)  # this should not overwrite the signature just made

        # 3. return the info useful for the ots proof: pivot_pt, [tx = prepend || ephemeral_pubkey_x || append]
        i = tx.raw.find(ephemeral_pubkey_x.hex())
        prepend = x(tx.raw[:i])
        append = x(tx.raw[i + len(ephemeral_pubkey_x.hex()):])
        # return pivot_pt_encoded, prepend, ephemeral_pubkey, append
        print("pivot_pt", bytes(pivot_pt_encoded).hex())
        print("prepend", prepend.hex())
        print("eph_pub", ephemeral_pubkey_x.hex())
        print("append", append.hex())
        # the ots proof (s2c_commit -> txid) will be something like:
        # Timestamp: s2c_commit
        # OpPrepend pivot_pt
        # OpSecp256k1Commitment
        # OpPrepend prepend
        # OpAppend append
        # OpSha256
        # OpSha256  ((w)txid in little endian)

    # dialog functions

    @hook
    def transaction_dialog(self, d):
        d.timestamp_button = b = QPushButton(_("Timestamp"))
        b.clicked.connect(lambda: self.add_op_return_commitment(d))
        d.buttons.insert(0, b)

        commit_s2c = hashlib.sha256(b'Hello world!').digest()
        d.timestamp_button = b = QPushButton(_("S2C"))
        b.clicked.connect(lambda: self.sign_to_contract(d.tx, d.wallet, commit_s2c))
        d.buttons.insert(1, b)

        b = d.buttons[3]  # broadcast button
        # b = d.buttons[2]  # broadcast button
        b.clicked.connect(lambda: self.upgrade_timestamps_txid(d.tx))

    def add_op_return_commitment(self, d):
        # d.timestamp_button.setDisabled(True)  # here?
        self.timestamp_op_return(d.tx)
        d.close()
        show_transaction(d.tx, d.main_window)

    @hook
    def transaction_dialog_update(self, d):
        # timestamp is disabled iff tx has an op_return output
        if any([o[0] == 2 for o in d.tx.outputs()]):
            d.timestamp_button.setDisabled(True)

    @hook
    def init_menubar_tools(self, window, tools_menu):
        tools_menu.addSeparator()
        tools_menu.addAction(_("&Timestamps"), partial(self.timestamp_dialog, window))

    def timestamp_dialog(self, window):

        d = WindowModalDialog(window, _("Timestamps"))
        vbox = QVBoxLayout(d)
        from .timestamp_list import TimestampList
        self.tlist = TimestampList(window, self.proofs_storage_file.db)  # FIXME: table with more fields, bigger dialog
        vbox.addWidget(self.tlist)

        # FIXME: disable button_upgrade if there is nothing to upgrade AND/OR highlight some rows in the table

        def print_db():
            print("___ file db start ___", len(self.proofs_storage_file.db), "proof(s) in db")
            for d in self.proofs_storage_file.db:
                print("  - path:", d["path"])
                print("  - status:", d["status"])
                print("  - mtt:", d["mtt"])
                print("  - txid:", d["txid"])
                print("  - block:", d["block"])
                #print("  - detached_timestamp:")
                #f = FileData()
                #f.from_db(d)
                #print(f.detached_timestamp.timestamp.str_tree(verbosity=1))
                print()
            print("___ file db end _____")

            print("___ calendar db start ___", len(self.proofs_storage_calendar.db), "proof(s) in db")
            for d in self.proofs_storage_calendar.db:
                print("  - link:", d["link"])
                print("  - tip:", d["tip"])
                print("  - mtt:", d["mtt"])
                #print("  - timestamp:")
                #c = CalendarData()
                #c.from_db(d)
                #print(c.timestamp.str_tree(verbosity=1))
            print("___ calendar db end _____")

        button_add_file = EnterButton(_('Add new file'), partial(self.open_file, window))
        button_upgrade = EnterButton(_('Upgrade'), partial(self.upgrade_dialog, window))
        button_temp = EnterButton(_('Print db (temporary)'), print_db)

        vbox.addWidget(button_add_file)
        vbox.addWidget(button_upgrade)
        vbox.addWidget(button_temp)

        return bool(d.exec_())

    def open_file(self, window):
        default_folder = "/home/leonardo/PycharmProjects/plugin5/File2Timestamp"
        filename, __ = QFileDialog.getOpenFileName(window, "Select a new file to timestamp", default_folder)
        if not filename:
            return
        self.add_new_file(filename)
        self.tlist.on_update()

    def upgrade_dialog(self, window):
        self.upgrade_timestamps_block(window.wallet, window.network)
        self.tlist.db = self.proofs_storage_file.db
        self.tlist.on_update()

    # settings functions

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        return EnterButton(_('Settings'), partial(self.settings_dialog, window))

    def settings_dialog(self, window):
        d = WindowModalDialog(window, _("Timestamp settings"))
        calendar = EnterButton(_('Calendars settings'), partial(self.calendars_dialog, window))
        commitment = EnterButton(_('Commitment method'), partial(self.commitment_method_dialog, window))
        vbox = QVBoxLayout(d)
        vbox.addWidget(calendar)
        vbox.addWidget(commitment)
        vbox.addSpacing(20)
        vbox.addLayout(Buttons(OkButton(d)))
        return bool(d.exec_())

    def calendars_dialog(self, window):

        d = WindowModalDialog(window, _("Calendar settings"))
        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel("Standard Calendar(s):"))
        for link in standard_calendars:
            vbox.addWidget(QLabel(" - " + link))
        vbox.addSpacing(10)
        vbox.addWidget(QLabel("Extra Calendar:"))
        grid = QGridLayout()
        new_link = QLineEdit()
        add_button = EnterButton(_('Add'), partial(self.add_new_calendar_dialog, new_link, vbox))
        grid.addWidget(new_link, 0, 0)
        grid.addWidget(add_button, 0, 1)
        for link in self.extra_calendars:
            vbox.addWidget(QLabel(" - " + link))
        vbox.addLayout(grid)
        vbox.addStretch()
        # vbox.addWidget(OkButton(d))  # add ok button?

        return bool(d.exec_())

    def add_new_calendar_dialog(self, new_link, vbox):
        # FIXME: manage error if the calendar is not working
        if self.add_new_calendar(new_link.text()):
            vbox.addWidget(QLabel(" - " + new_link.text()))

    def commitment_method_dialog(self, window):
        # FIXME: do it again

        self.commit_via_opr = True
        self.commit_via_stc = False

        d = WindowModalDialog(window, _("Commitment Method Settings"))

        vbox = QVBoxLayout(d)
        grid = QGridLayout()

        def check_state_opr():
            self.commit_via_opr = c_opr.isChecked()

        def check_state_stc():
            self.commit_via_stc = c_stc.isChecked()

        c_opr = QRadioButton(_('Commit using OP_RETURN'))
        c_opr.setChecked(self.commit_via_opr)
        c_opr.toggled.connect(check_state_opr)
        c_stc = QRadioButton(_('Commit using sign-to-contract'))
        c_stc.setChecked(self.commit_via_stc)
        c_stc.toggled.connect(check_state_stc)

        h_opr = HelpButton("Include commitment inside a OP_RETURN. "
                           "\nThis will make your transaction 43 bytes longer, nevertheless the amounts (and hence the "
                           "fees) won't be modified, as result you will obtain a transaction with lower sat/vbytes "
                           "which may slow down its confirmation time."
                           "\nSign-to-contract doesn't have this problem, consider using only that.")
        h_stc = HelpButton("Include commitment inside the signature using sign-to-contract")

        grid.addWidget(c_opr, 1, 1)
        grid.addWidget(h_opr, 1, 2)
        grid.addWidget(c_stc, 2, 1)
        grid.addWidget(h_stc, 2, 2)

        vbox.addLayout(grid)
        vbox.addSpacing(20)
        vbox.addLayout(Buttons(OkButton(d)))

        return bool(d.exec_())


# FIXME: partial or lambda?
