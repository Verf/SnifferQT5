# /usr/bin/env python3
# coding: utf-8

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_Main(object):
    def setupUi(self, Main):
        Main.setObjectName("Main")
        Main.resize(1200, 800)
        self.main_layout = QtWidgets.QVBoxLayout(Main)
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        self.main_layout.setSpacing(10)
        self.main_layout.setObjectName("main_layout")

        self.control_vbox = QtWidgets.QHBoxLayout()
        self.control_vbox.setContentsMargins(10, 10, 10, 10)
        self.control_vbox.setSpacing(10)
        self.control_vbox.setObjectName("control_vbox")

        self.device_cbox = QtWidgets.QComboBox(Main)
        self.device_cbox.setObjectName("device_cbox")
        self.control_vbox.addWidget(self.device_cbox)

        self.sniff_button = QtWidgets.QPushButton(Main)
        self.sniff_button.setObjectName("sniff_button")
        self.control_vbox.addWidget(self.sniff_button)

        self.filter_input = QtWidgets.QLineEdit(Main)
        self.filter_input.setObjectName("filter_input")
        self.control_vbox.addWidget(self.filter_input)

        self.filter_button = QtWidgets.QPushButton(Main)
        self.filter_button.setObjectName("filter_button")
        self.control_vbox.addWidget(self.filter_button)
        self.main_layout.addLayout(self.control_vbox)
        
        self.packet_table = QtWidgets.QTableWidget(Main)
        self.packet_table.setObjectName("packet_table")
        self.main_layout.addWidget(self.packet_table)

        self.details_tree = QtWidgets.QTreeWidget(Main)
        self.details_tree.setObjectName("details_tree")
        self.main_layout.addWidget(self.details_tree)

        self.retranslateUi(Main)
        QtCore.QMetaObject.connectSlotsByName(Main)

    def retranslateUi(self, Main):
        _translate = QtCore.QCoreApplication.translate
        Main.setWindowTitle(_translate("Main", "Sniffer"))
        self.sniff_button.setText(_translate("Main", "Catch"))
        self.filter_button.setText(_translate("Main", "Filter"))

