#/usr/bin/env python3
# coding: utf-8
import sys
from PyQt5.QtWidgets import QDialog, QApplication, QTableWidget, QTableWidgetItem, QTreeWidgetItem
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
        self.ipp = {"6":"TCP", "17":"UDP", "1":"ICMP", "2":"IGMP"}
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
        prase = Praser(raw)
        packet = [ptime, plen, prase]
        self.packet_list.append(packet)
        if prase.type == "0x0800":
            # IP
            self.set_table_row(
                    ptime,
                    prase.packet.ip_src,
                    prase.packet.ip_dst,
                    self.ipp[prase.packet.ip_protocol],
                    plen,
                    "None")
        elif prase.type == "0x0806":
            # ARP
            self.set_table_row(
                    ptime,
                    prase.mac_src,
                    prase.mac_dst,
                    "ARP",
                    plen,
                    "None")
        else:
            # Unknow Protocol
            self.set_table_row(
                    ptime,
                    prase.mac_src,
                    prase.mac_dst,
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

    def set_tree_row(self,row_num):
        packet = self.packet_list[row_num]
        prase = packet[2]
        frame_root = QTreeWidgetItem(["Frame {0}: {1} byte on {2}".format(str(row_num+1), packet[1], self.device)])
        frame_root.addChild(QTreeWidgetItem(["Interface Name: " + self.device]))
        frame_root.addChild(QTreeWidgetItem(["Encapsulation Type: Enthernet (1)"]))
        frame_root.addChild(QTreeWidgetItem(["TimeStamps: " + packet[0]]))
        frame_root.addChild(QTreeWidgetItem(["Frame Number: " + str(row_num)]))
        frame_root.addChild(QTreeWidgetItem(["Frame Lenght: " + packet[1]]))
        self.details_tree.addTopLevelItem(frame_root)

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

