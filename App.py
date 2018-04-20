# /usr/bin/env python3
# coding: utf-8
import sys
from PyQt5.QtWidgets import QDialog, QApplication, \
        QTableWidget, QTableWidgetItem, QTreeWidgetItem
from Gui import Ui_Main
from Sniffer import Sniffer
from Praser import Praser
import pcapy


class AppWindow(QDialog, Ui_Main):
    def __init__(self):
        super(AppWindow, self).__init__()
        self.device = None
        self.thread = None
        self.packet_list = []
        self.setupUi(self)
        self.init_ui()

    def init_ui(self):
        # Set device list
        device_list = pcapy.findalldevs()
        for i in device_list:
            self.device_cbox.addItem(i)
        # Sniff Button
        self.sniff_button.setCheckable(True)
        self.sniff_button.clicked[bool].connect(self.sniff_control)
        # Filter Button
        self.filter_button.clicked.connect(self.filter_clicked)
        # Packet Table
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels([
            "Time",
            "Source",
            "Destination",
            "Protocol",
            "Length",
            "Info"])
        self.packet_table.clicked.connect(self.row_selected)
        # Details Tree
        self.details_tree.setHeaderHidden(True)

    def sniff_control(self, pressed):
        if pressed:
            dev = self.device_cbox.currentText()
            if dev:
                self.device = dev
                self.thread = Sniffer(dev)
                self.thread.sig.connect(self.pack_receive)
                self.thread.start()
            else:
                print("Device is empty!")
        else:
            self.thread.stop()

    def filter_clicked(self):
        pass

    def pack_receive(self):
        sender = self.sender()
        pack = sender.get_pack()
        ptime = str(pack[0])
        plen = str(pack[1])
        raw = pack[2]
        prs = Praser(raw)
        prs.prase()
        pk = prs.packet
        packet = [ptime, plen, pk]
        self.packet_list.append(packet)
        if pk["FP"][0] == "0":
            # IP
            self.set_table_row(
                    ptime,
                    pk["IPv4"]["Source"],
                    pk["IPv4"]["Destination"],
                    pk["IPv4"]["Protocol"][-4:-1],
                    plen,
                    pk["Info"])
        elif pk["FP"][0] == "1":
            # ARP
            self.set_table_row(
                    ptime,
                    pk["ARP"]["Source"],
                    pk["ARP"]["Destination"],
                    "ARP",
                    plen,
                    pk["Info"])
        else:
            # Unknow Protocol
            self.set_table_row(
                    ptime,
                    pk["Ethernet"]["Source"],
                    pk["Ethernet"]["Destination"],
                    "Unknow",
                    plen,
                    "None")

    def set_table_row(self, ptime, src, dst, ptcl, plen, info):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        self.packet_table.setItem(row, 0, QTableWidgetItem(ptime))
        self.packet_table.setItem(row, 1, QTableWidgetItem(src))
        self.packet_table.setItem(row, 2, QTableWidgetItem(dst))
        self.packet_table.setItem(row, 3, QTableWidgetItem(ptcl))
        self.packet_table.setItem(row, 4, QTableWidgetItem(plen))
        self.packet_table.setItem(row, 5, QTableWidgetItem(info))

    def set_tree_row(self, row_num):
        pack = self.packet_list[row_num]
        ptime = pack[0]
        plen = pack[1]
        pk = pack[2]
        frame_root = QTreeWidgetItem(["Frame {0}: {1} byte on {2}".format(str(row_num+1), plen, self.device)])
        frame_root.addChild(QTreeWidgetItem(["Interface Name: " + self.device]))
        frame_root.addChild(QTreeWidgetItem(["Encapsulation Type: Enthernet (1)"]))
        frame_root.addChild(QTreeWidgetItem(["TimeStamps: " + ptime]))
        frame_root.addChild(QTreeWidgetItem(["Frame Number: " + str(row_num+1)]))
        frame_root.addChild(QTreeWidgetItem(["Frame Lenght: " + plen]))
        self.details_tree.addTopLevelItem(frame_root)
        for k, v in pk.items():
            if k not in ["FP", "Info", "Others"]:
                tmp_root = QTreeWidgetItem([k])
                for ki, vi in v.items():
                    tmp_root.addChild(QTreeWidgetItem([ki + ": " + vi]))
                self.details_tree.addTopLevelItem(tmp_root)

    def row_selected(self):
        sender = self.sender()
        row_num = sender.currentRow()
        self.details_tree.clear()
        self.set_tree_row(row_num)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = AppWindow()
    w.show()
    sys.exit(app.exec_())

