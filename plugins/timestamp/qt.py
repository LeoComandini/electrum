from PyQt5.QtGui import *
from electrum.plugins import BasePlugin, hook
from electrum.i18n import _
from PyQt5.QtWidgets import (QHBoxLayout, QVBoxLayout, QGridLayout, QPushButton, QLabel, QLineEdit, QFileDialog)
from electrum_gui.qt import EnterButton
from electrum_gui.qt.util import ThreadedButton, Buttons
from electrum_gui.qt.util import WindowModalDialog, OkButton, CloseButton, HelpButton, QRadioButton
from electrum_gui.qt.transaction_dialog import show_transaction
from electrum_gui.qt.main_window import StatusBarButton
from electrum.util import timestamp_to_datetime

from bitcoin.core import *
from opentimestamps.core.timestamp import *
from opentimestamps.core.serialize import BytesSerializationContext, BytesDeserializationContext
from opentimestamps.core.notary import UnknownAttestation, BitcoinBlockHeaderAttestation
from opentimestamps.timestamp import *

from functools import partial
import requests
import json
import base64

# PB1:
# what if the signature is in the witness? (e.g. in s2c)
# Electrum servers cannot be asked for the witness path,
# someone else (running a full node) should be asked

# PB2:
# should the case in which the tx is malleated bya 3rd part be managed?

# FIXME: what if I want to timestamp raw data instead of a file? should I add a "Data" class?


# ___ deprecated ______________________________________________

"""
class CalendarData:

    def __init__(self, link=None):
        self.link = link
        self.status = None  # aggregated, broadcasted  # FIXME: is this useful?
        self.tip = None
        self.mtt = None
        self.timestamp = None

    def ask_tip(self):
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


standard_calendars = ["https://testnet.calendar.eternitywall.com/tip"]
json_path_calendar = "db_calendar.json"


def add_new_calendar(self, link):
    # add an extra calendar
    # FIXME: check if the calendar is working

    if link in standard_calendars:
        return False
    else:
        self.extra_calendars += [link]
        return True
        
def collect_tips(self):
    # Collect tips from calendars
    # previous calendar incomplete proofs will be deleted

    self.proofs_storage_calendar.incomplete_proofs = []
    for link in standard_calendars + self.extra_calendars:
        print("asking tip to", link)
        c = CalendarData(link)
        c.ask_tip()  # which errors could occur?
        self.proofs_storage_calendar.incomplete_proofs += [c]
    self.proofs_storage_calendar.update_db()
    
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



    @hook
    def transaction_dialog(self, d):
        d.timestamp_button = b = QPushButton(_("Timestamp"))
        b.clicked.connect(lambda: self.add_op_return_commitment(d))
        d.buttons.insert(0, b)

        b = d.buttons[2]  # broadcast button
        b.clicked.connect(lambda: self.upgrade_timestamps_txid(d.tx))
        
    

    def upgrade_timestamps_txid(self, wallet):
        #Upgrade timestamps until txid

        # read from the json so the timestamps common structure is lost anyway
        self.proofs_storage_file.read_json()

        for txid, tx in wallet.transactions.items():
            if txid in wallet.verified_tx.keys():
                for out in tx.outputs():
                    if out[0] == 2:  # type, script, amount
                        # agt -> txid
                        agt = out[1][4:]  # drop "6a20" op_return and op_pushdata(32)
                        i = tx.raw.find(agt)
                        prepend = x(tx.raw[:i])
                        append = x(tx.raw[i + len(agt):])
                        t_agt = Timestamp(x(agt))
                        t = t_agt.ops.add(OpPrepend(prepend))
                        t = t.ops.add(OpAppend(append))
                        t = t.ops.add(OpSHA256())
                        t = t.ops.add(OpSHA256())  # txid in little endian
                        # merge the timestamps
                        for f in self.proofs_storage_file.incomplete_proofs:
                            tf = roll_timestamp(f.detached_timestamp.timestamp)
                            if tf.msg == x(agt):
                                tf.merge(t_agt)  # timestamp upgraded
                                f.status = "pending"
                                f.txid = t.msg[::-1].hex()
        self.update_storage(clean_memory=True)

"""

# ____ util ________________________________________________________________________


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


# ____ data containers ______________________________________________________________


class FileData:

    def __init__(self):
        self.path = None
        self.status = None  # tracked, aggregated, pending, completed
        self.agt = None  # aggregation tip
        self.txid = None
        self.block = None
        self.date = None
        self.detached_timestamp = None

    def from_file(self, path):
        # what should happen if the file does not exist
        self.path = path
        self.status = "tracked"
        self.agt = None
        self.txid = None
        self.block = None
        self.date = None
        with open(self.path, "rb") as fo:
            self.detached_timestamp = DetachedTimestampFile.from_fd(OpSHA256(), fo)

    def from_db(self, d):
        self.path = d["path"]
        self.status = d["status"]
        self.agt = bytes.fromhex(d["agt"]) if d["agt"] else d["agt"]
        self.txid = d["txid"]
        self.block = d["block"]
        self.date = d["date"]
        self.detached_timestamp = DetachedTimestampFile.deserialize(BytesDeserializationContext(b64string_to_bytes(d["detached_timestamp"])))
        post_deserialize(self.detached_timestamp.timestamp)

    def as_dict(self):
        d = dict()
        d["path"] = self.path
        d["status"] = self.status
        d["agt"] = self.agt.hex() if self.agt else self.agt
        d["txid"] = self.txid
        d["block"] = self.block
        d["date"] = self.date
        pre_serialize(self.detached_timestamp.timestamp)
        ctx = BytesSerializationContext()
        self.detached_timestamp.serialize(ctx)
        d["detached_timestamp"] = bytes_to_b64string(ctx.getbytes())
        ft = roll_timestamp(self.detached_timestamp.timestamp)
        ft.attestations = set()
        return d

    def write_ots(self):
        # assert or return some error?
        assert self.status == "complete"
        assert self.block == sorted(roll_timestamp(self.detached_timestamp.timestamp).attestations)[0].height
        ctx = BytesSerializationContext()
        self.detached_timestamp.serialize(ctx)
        with open(self.path + ".ots", "wb") as fw:
            fw.write(ctx.getbytes())


class ProofsStorage:
    """Container for complete and incomplete proofs"""

    def __init__(self, json_path):
        self.json_path = json_path
        self.db = []  # list of dicts
        self.incomplete_proofs = []  # list of FileData
        self.read_json()

    def read_json(self):
        try:
            with open(self.json_path, "r") as f:
                self.incomplete_proofs = []
                self.db = []
                self.db = json.load(f)
                for d in self.db:
                    if d["status"] != "complete":
                        f = FileData()
                        f.from_db(d)
                        self.incomplete_proofs += [f]
        except FileNotFoundError:
            pass  # the json will be created later

    def write_json(self):
        with open(self.json_path, 'w') as f:
            json.dump(self.db, f)

    def update_db(self):
        try:  # non empty list of files
            db_complete = [d for d in self.db if d["status"] == "complete"]
            self.db = db_complete
        except KeyError:  # empty list
            self.db = []
        for i in self.incomplete_proofs:
            self.db += [i.as_dict()]

    def add_proof(self, proof):
        for d in self.db:
            if proof.path == d["path"]:
                return False
        for i in self.incomplete_proofs:
            if proof.path == i.path:
                return False
        self.incomplete_proofs += [proof]
        self.db += [proof.as_dict()]
        self.write_json()
        return True


json_path_file = "/home/leonardo/PycharmProjects/plugin6/electrum/db_file.json"
default_blocks_until_confirmed = 0  # set to 0 for faster testing, should be 6
default_folder = "/home/leonardo/PycharmProjects/plugin6/File2Timestamp"


class Plugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.proofs_storage_file = ProofsStorage(json_path_file)
        self.timestamp_list = None

    def track_new_file(self, path):
        f = FileData()
        f.from_file(path)
        return self.proofs_storage_file.add_proof(f)

    def aggregate_timestamps(self):
        file_timestamps = []
        for f in self.proofs_storage_file.incomplete_proofs:
            if f.status != "pending":
                f.from_file(f.path)  # overwrite the previous detached timestamps
                f.status = "aggregated"
                file_timestamps += [nonce_timestamp(f.detached_timestamp.timestamp)]
        if not file_timestamps:
            return None
        else:
            t = make_merkle_tree(file_timestamps)
            for f in self.proofs_storage_file.incomplete_proofs:
                if f.status == "aggregated":
                    f.agt = roll_timestamp(f.detached_timestamp.timestamp).msg
            self.update_storage()
        return t.msg

    def upgrade_timestamps_txs(self, wallet):
        for txid, tx in wallet.transactions.items():
            if txid in wallet.verified_tx.keys():
                self.upgrade_timestamps_tx(tx)

    def upgrade_timestamps_tx(self, tx):
        for category, script, amount in tx.outputs():
            if category == 2:  # agt -> txid
                # FIXME: test the case if the tx is segwit
                agt = script[4:]  # drop "6a20" op_return and op_pushdata(32)
                i = tx.raw.find(agt)
                prepend = x(tx.raw[:i])
                append = x(tx.raw[i + len(agt):])
                t_agt = Timestamp(x(agt))
                t = t_agt.ops.add(OpPrepend(prepend))
                t = t.ops.add(OpAppend(append))
                t = t.ops.add(OpSHA256())
                t = t.ops.add(OpSHA256())  # txid in little endian
                for f in self.proofs_storage_file.incomplete_proofs:
                    tf = roll_timestamp(f.detached_timestamp.timestamp)
                    if tf.msg == x(agt):
                        tf.merge(t_agt)  # timestamp upgraded
                        f.status = "pending"
                        f.txid = t.msg[::-1].hex()
        self.update_storage()

    def upgrade_timestamps_block(self, wallet, network):
        local_height = network.get_local_height()
        txid_pending = set([f.txid for f in self.proofs_storage_file.incomplete_proofs if f.status == "pending"])
        for txid in txid_pending:
            try:
                tx_height, timestamp, _ = wallet.verified_tx[txid][0]
                is_upgradable = (local_height - tx_height >= default_blocks_until_confirmed)
            except KeyError:
                is_upgradable = False
            if is_upgradable:  # txid -> block
                t = proof_from_txid_to_block(txid, tx_height, network)
                for f in self.proofs_storage_file.incomplete_proofs:
                    tf = roll_timestamp(f.detached_timestamp.timestamp)
                    if tf.msg == t.msg:
                        tf.merge(t)
                        f.status = "complete"
                        f.block = tx_height
                        f.date = timestamp_to_datetime(timestamp)
                        f.write_ots()
                        # f.detached_timestamp = None
        self.update_storage()

    def update_storage(self):
        self.proofs_storage_file.update_db()
        self.proofs_storage_file.write_json()
        self.proofs_storage_file.read_json()  # drop timestamps common structure to stay more general

    def timestamp_op_return(self, tx):
        commit = self.aggregate_timestamps()
        if commit is not None:
            script = bytes.fromhex("6a") + len(commit).to_bytes(1, "big") + commit
            tx.add_outputs([(2, script.hex(), 0)])

    # dialog functions

    @hook
    def transaction_dialog(self, d):
        d.timestamp_button = b = QPushButton(_("Timestamp"))
        b.clicked.connect(lambda: self.add_op_return_commitment(d))
        d.buttons.insert(0, b)

        b = d.buttons[2]  # broadcast button
        b.clicked.connect(lambda: self.upgrade_timestamps_tx(d.tx))

    def add_op_return_commitment(self, d):
        self.timestamp_op_return(d.tx)
        d.close()
        show_transaction(d.tx, d.main_window)

    @hook
    def transaction_dialog_update(self, d):
        # timestamp is disabled if there is nothing to timestamp or tx has an op_return output
        if len(self.proofs_storage_file.incomplete_proofs) == 0 or any([o[0] == 2 for o in d.tx.outputs()]):
            d.timestamp_button.setDisabled(True)

    @hook
    def init_menubar_tools(self, window, tools_menu):
        tools_menu.addSeparator()
        tools_menu.addAction(_("&Timestamps"), partial(self.timestamp_dialog, window))

    def timestamp_dialog(self, window):
        d = WindowModalDialog(window, _("Timestamps"))
        d.setMinimumSize(500, 100)
        vbox = QVBoxLayout(d)
        from .timestamp_list import TimestampList
        self.timestamp_list = TimestampList(window, self.proofs_storage_file.db)
        vbox.addWidget(self.timestamp_list)
        button_add_file = EnterButton(_('Add new file'), partial(self.open_file, window))
        button_upgrade = EnterButton(_('Upgrade'), partial(self.upgrade_dialog, window))
        grid = QGridLayout()
        grid.addWidget(button_add_file, 0, 0)
        grid.addWidget(button_upgrade, 0, 1)
        vbox.addLayout(grid)
        return bool(d.exec_())

    def open_file(self, window):
        filename, __ = QFileDialog.getOpenFileName(window, "Select a new file to timestamp", default_folder)
        if not filename:
            return
        if self.track_new_file(filename):
            self.timestamp_list.on_update()
        else:
            self.duplicate_path_dialog(window)

    def duplicate_path_dialog(self, window):
        d = WindowModalDialog(window, _("Duplicate file"))
        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel("Duplicate file cannot be added to the timestamp storage"))
        vbox.addLayout(Buttons(OkButton(d)))
        d.exec_()

    def upgrade_dialog(self, window):
        self.upgrade_timestamps_txs(window.wallet)  # useful only if the tx is broadcasted without the plugin
        self.upgrade_timestamps_block(window.wallet, window.network)
        self.timestamp_list.db = self.proofs_storage_file.db
        self.timestamp_list.on_update()


# FIXME: if a tx get stuck the corresponding timestamp can never be completed, add a fun to erase pending timestamps?
