# /usr/bin/env python3
# coding: utf-8
from PyQt5.QtCore import QThread, pyqtSignal
from datetime import datetime
import pcapy


class Sniffer(QThread):
    sig = pyqtSignal()

    def __init__(self, dev, parent=None):
        super(Sniffer, self).__init__(parent)
        self._run = True
        self._dev = dev
        self.pack_list = []

    def run(self):
        cap = pcapy.open_live(self._dev, 0, 1, 0)
        start_time = datetime.now()
        while self._run:
            header, packet = cap.next()
            if len(packet) >= 14:
                plen = header.getlen()
                current_time = datetime.now()
                ptime = current_time - start_time
                ptime = ptime.total_seconds()
                pack = [ptime, plen, packet]
                self.pack_list.append(pack)
                self.sig.emit()

    def stop(self):
        self._run = False

    def get_pack(self):
        pack = self.pack_list.pop(0)
        return pack
