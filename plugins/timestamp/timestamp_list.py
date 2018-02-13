from electrum.i18n import _
from electrum.bitcoin import is_address
from electrum.util import block_explorer_URL
from electrum.plugins import run_hook
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import (
    QAbstractItemView, QFileDialog, QMenu, QTreeWidgetItem)
from electrum_gui.qt.util import MyTreeWidget


class TimestampList(MyTreeWidget):
    filter_columns = [0, 1]  # Key, Value

    def __init__(self, parent, db):
        MyTreeWidget.__init__(self, parent, self.create_menu, [_('Path'), _('Status'), _('Aggregated Merkle Tip'), _('TXID'), _('Block')], 0, [0])
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)

        self.db = db
        self.on_update()

    def create_menu(self, position):
        menu = QMenu()
        selected = self.selectedItems()

    def on_update(self):
        item = self.currentItem()
        current_path = item.data(0, Qt.UserRole) if item else None
        self.clear()
        for d in self.db:  # FIXME: order in the desired way
            path, status, mtt, txid, block = d["path"], d["status"], d["mtt"], d["txid"], d["block"]
            if mtt is not None:
                mtt = d["mtt"][:8] + "..."
            if txid is not None:
                txid = d["txid"][:8] + "..."
            if d["block"] is not None:
                block = str(block)
            item = QTreeWidgetItem([path, status, mtt, txid, block])
            item.setData(0, Qt.UserRole, path)
            self.addTopLevelItem(item)
            if path == current_path:
                self.setCurrentItem(item)
