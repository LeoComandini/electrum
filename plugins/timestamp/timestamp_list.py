from electrum.i18n import _
from electrum.bitcoin import is_address
from electrum.util import block_explorer_URL
from electrum.plugins import run_hook
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import (
    QAbstractItemView, QFileDialog, QMenu, QTreeWidgetItem)
from electrum_gui.qt.util import MyTreeWidget
from electrum.util import timestamp_to_datetime
from electrum_gui.qt.util import time


class TimestampList(MyTreeWidget):
    filter_columns = [0, 1]  # Key, Value

    def __init__(self, parent, db):
        MyTreeWidget.__init__(self, parent, self.create_menu, [_('Path'), _('Date'), _('Aggregated Tip'), _('TXID'), _('Block')], 0, [0])
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.db = db
        if db:
            self.on_update()

    def create_menu(self):
        pass

    def on_update(self):
        item = self.currentItem()
        current_path = item.data(0, Qt.UserRole) if item else None
        self.clear()
        for d in ordered_db(self.db):
            path = d["path"]
            date = d["date"] if d["date"] else "To be defined"
            status = d["status"]
            agt = d["agt"][:8] if d["agt"] else d["agt"]
            txid = d["txid"][:8] if d["txid"] else d["txid"]
            block = str(d["block"]) if d["block"] else d["block"]
            item = QTreeWidgetItem([path, date, agt, txid, block])
            if status == "tracked":
                pic = "status_connected_proxy.png"
            elif status == "aggregated":
                pic = "status_lagging.png"
            elif status == "pending":
                pic = "clock1.png"
            else:  # confirmed
                pic = "confirmed.png"
            icon = QIcon(":icons/" + pic)
            item.setIcon(0, icon)
            item.setToolTip(0, status)
            item.setData(0, Qt.UserRole, path)
            self.addTopLevelItem(item)
            if path == current_path:
                self.setCurrentItem(item)


def ordered_db(db):
    odb = []
    odb += sorted([d for d in db if d["status"] == "complete"], key=lambda b: b["date"])
    for s in ["pending", "aggregated", "tracked"]:
        odb += sorted([d for d in db if d["status"] == s], key=lambda b: b["path"])
    return odb


