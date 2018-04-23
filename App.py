# /usr/bin/env python3
# coding: utf-8
import sys
from PyQt5.QtWidgets import QDialog, QApplication, \
        QTableWidget, QTableWidgetItem, QTreeWidgetItem, QLabel
from Gui import Ui_Main
from Sniffer import Sniffer
from Praser import Praser
import pcapy
import Tools


class AppWindow(QDialog, Ui_Main):
    def __init__(self):
        super(AppWindow, self).__init__()
        self.device = None
        self.filter = ""
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
        self.packet_table.horizontalHeader().setStretchLastSection(True)
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
        # raw text
        self.raw_text.setFontFamily("Monospace")

    def sniff_control(self, pressed):
        if pressed:
            if self.packet_list:
                self.packet_list = []
                while self.packet_table.rowCount() > 0:
                    self.packet_table.removeRow(0)
            dev = self.device_cbox.currentText()
            if dev:
                self.device = dev
                self.thread = Sniffer(self.device, self.filter)
                self.thread.sig.connect(self.pack_receive)
                self.thread.start()
            else:
                print("Device is empty!")
        else:
            self.thread.stop()

    def filter_clicked(self):
        self.filter = str(self.filter_input.text())

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
        self.set_table(packet)

    def set_table(self, packet):
        ptime = packet[0]
        plen = packet[1]
        pk = packet[2]
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
                    pk["ARP"]["Sender IP"],
                    pk["ARP"]["Target IP"],
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
        label = QLabel("Descriptions")
        label.setWordWrap(True)
        frame_root.addChild(QTreeWidgetItem(["Interface Name: " + self.device]))
        frame_root.addChild(QTreeWidgetItem(["Encapsulation Type: Enthernet (1)"]))
        frame_root.addChild(QTreeWidgetItem(["TimeStamps: " + ptime]))
        frame_root.addChild(QTreeWidgetItem(["Frame Number: " + str(row_num+1)]))
        frame_root.addChild(QTreeWidgetItem(["Frame Lenght: " + plen]))
        self.details_tree.addTopLevelItem(frame_root)
        for k, v in pk.items():
            if k not in ["FP", "Info", "Others", "Raw"]:
                tmp_root = QTreeWidgetItem([k])
                for ki, vi in v.items():
                    item = QTreeWidgetItem()
                    word = QLabel(ki + ": " + vi)
                    if ki == "Data":
                        word.setWordWrap(True)
                        wlen = round(len(vi)/170)
                        word.setFixedHeight(word.fontMetrics().height() * wlen)
                    tmp_root.addChild(item)
                    self.details_tree.setItemWidget(item, 0, word)
                self.details_tree.addTopLevelItem(tmp_root)

    def set_raw_text(self, row_num):
        pack = self.packet_list[row_num]
        pk = pack[2]
        raw_text = pk["Raw"]
        line_num = 0
        for i in range(0, len(raw_text), 32):
            line_num += 1
            raw = raw_text[i:i+32]
            tmp = []
            for j in range(0, len(raw), 2):
                tmp.append(raw[j:j+2])
            fbt = " ".join(tmp[:8])
            lbt = " ".join(tmp[8:])
            tmp_tex = "{0}  {1}".format(fbt, lbt)
            if len(tmp_tex) < 49:
                tmp_tex += " "*(49-len(tmp_tex))
            tmp_tex += "    " + Tools.h2a(raw)
            tex = "0x{0:04x}  {1}".format(16*line_num, tmp_tex)
            self.raw_text.append(tex)

    def row_selected(self):
        sender = self.sender()
        row_num = sender.currentRow()
        self.details_tree.clear()
        self.raw_text.clear()
        self.set_tree_row(row_num)
        self.set_raw_text(row_num)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = AppWindow()
    w.show()
    sys.exit(app.exec_())

