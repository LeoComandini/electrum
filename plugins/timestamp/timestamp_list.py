from electrum.i18n import _
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QAbstractItemView, QTreeWidgetItem
from electrum_gui.qt.util import MyTreeWidget


class TimestampList(MyTreeWidget):
    filter_columns = [0, 1]

    def __init__(self, parent, db):
        MyTreeWidget.__init__(self, parent, self.create_menu, [_('Path'), _('Date')], 0, [0])
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
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
            date = d["date"] if d["date"] else "Yet to be confirmed"
            status = d["status"]
            agt = d["agt"] if d["agt"] else ""
            txid = d["txid"] if d["txid"] else ""
            block = str(d["block"]) if d["block"] else ""
            tool_tip = "Status:   " + status + \
                       "\nAgg. tip: " + agt + \
                       "\nTXID:     " + txid + \
                       "\nBlock:    " + block
            item = QTreeWidgetItem([path, date])
            # use a selection of the available icons
            if status == "tracked":
                pic = "status_connected_proxy.png"  # blue circle
            elif status == "aggregated":
                pic = "status_lagging.png"  # brown circle
            elif status == "pending":
                pic = "clock1.png"
            else:  # confirmed
                pic = "confirmed.png"
            icon = QIcon(":icons/" + pic)
            item.setIcon(0, icon)
            item.setToolTip(0, tool_tip)
            item.setData(0, Qt.UserRole, path)
            self.addTopLevelItem(item)
            if path == current_path:
                self.setCurrentItem(item)


def ordered_db(db):
    odb = []
    for s in ["tracked", "aggregated", "pending"]:
        odb += sorted([d for d in db if d["status"] == s], key=lambda b: b["path"])
    odb += sorted([d for d in db if d["status"] == "complete"], key=lambda b: b["date"], reverse=True)
    return odb
