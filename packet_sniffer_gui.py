from PyQt5.QtWidgets import *
from PyQt5.QtCore import QObject, QThread, pyqtSignal, QSortFilterProxyModel
import sys
import pcapy
from struct import unpack
import socket
import time
import csv


class Worker(QThread):
	data = pyqtSignal(object)
	finished = pyqtSignal()
	
	
	def __init__(self):
		QThread.__init__(self)
		
		
	def run(self):
		cap = pcapy.open_live('en0', 65536, 1, 0)
		
		while True:
			
			global isRun
			if not isRun:
				#cap.close()
				print('Closed')
				break
			protocol_name, protocol, s_addr, d_addr = 'Other', 'Other', 'Other', 'Other'
			source_port, dest_port, info = '', '', ''
			(header, packet) = cap.next()
			#print('Running')
			
			# Ethernet header
			eth_header = packet[:14]
			eth = unpack('!6s6sH', eth_header)
			eth_proto = socket.ntohs(eth[2])
			if eth_proto == 8:
			# IP header
				ip_header = packet[14: 14+20]
				iph = unpack('!BBHHHBBH4s4s' , ip_header)
				version_ihl = iph[0]
				version = version_ihl >> 4
				ihl = version_ihl & 0xF
				iph_length = ihl * 4
				ttl = iph[5]
				protocol = iph[6]
				s_addr = socket.inet_ntoa(iph[8])
				d_addr = socket.inet_ntoa(iph[9])
				if protocol == 17:
					protocol_name = 'UDP'
					packet = packet[14+iph_length: 14+iph_length+8]
					header = unpack('!HHHH', packet)
					source_port = header[0]
					dest_port = header[1]
					checksum = header[3]
					info ='Checksum: {}'.format(checksum)
			
				elif protocol == 6: 
					protocol_name = 'TCP'
					t = 14 + iph_length
					packet = packet[t: t+20]
					tcph = unpack('!HHLLBBHHH', packet)
					source_port = tcph[0]
					dest_port = tcph[1]
					seq = tcph[2]
					ack = tcph[3]
					info = 'Seq: {}, ack: {}'.format(seq, ack)
					#info = str((seq, ack)) 
				
				elif protocol == 1:
					protocol_name = 'ICMP'
					t = 14 + iph_length
					packet = packet[t: t+4]
					icmph = unpack('!BBH', packet)
					info = 'Type: {}, Code: {}, Checksum: {}'.format(icmph[0], icmph[1], icmph[2])
			if protocol_name and protocol != 'Other':
				dataProduced = (protocol_name, str(protocol), s_addr, d_addr, str(source_port), str(dest_port), info)
				#self.data.emit('%s %s %s %s %s %s %s' % (protocol_name, str(protocol), s_addr, d_addr, str(source_port), str(dest_port), info))
				self.data.emit(dataProduced)
			
		self.quit()

class Window(QWidget):
	def __init__(self):
		QWidget.__init__(self)
		#self.setFixedHeight(600)
		layout = QVBoxLayout()
		self.setLayout(layout)
		
		
		self.tablewidget = QTableWidget()
		
		#rowPos = self.tablewidget.rowCount()
		self.tablewidget.setColumnCount(7)
		self.tablewidget.setHorizontalHeaderLabels(['Protocol', 'Protocol Number', 'Source IP', 'Destination IP', 'Source Port', 'Destination port', 'Information'])
		self.rowPos = 0
		
		self.tablewidget.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)
		
		self.button = QPushButton('Start Capturing')
		self.saveButton = QPushButton('Save output')
		self.openButton = QPushButton('Open file')
		
		layout.addWidget(self.button)
		#layout.addLayout(self.hboxlayout)
		layout.addWidget(self.tablewidget)
		layout.addWidget(self.saveButton)
		layout.addWidget(self.openButton)
		self.tablewidget.setMinimumHeight(400)
		self.tablewidget.setMinimumWidth(600)

		self.button.clicked.connect(self.startCapture)
		self.saveButton.clicked.connect(self.saveData)
		self.openButton.clicked.connect(self.opencsv)
		

	def startCapture(self):
	
		global isRun
		if self.button.text() == 'Start Capturing':
			isRun = True
			self.tablewidget.setRowCount(0)
			
			self.tablewidget.horizontalHeader().setStretchLastSection(True)
			self.tablewidget.resizeColumnToContents(6)
			self.threads = []
			self.button.setText('Stop Capturing')
			#self.button.setEnabled(False)
			self.worker = Worker()
			
			self.worker.data.connect(self.on_data_ready)
			
			self.threads.append(self.worker)
			self.worker.start()
		else:
			isRun = False

			print('Done')
			
				
			self.button.setText('Start Capturing')
		
	def on_data_ready(self, data_list):
	
		row = self.tablewidget.rowCount()
		
		self.tablewidget.setRowCount(row+1)
		self.tablewidget.setItem(row, 0, QTableWidgetItem(data_list[0]))
		self.tablewidget.setItem(row, 1, QTableWidgetItem(data_list[1]))
		self.tablewidget.setItem(row, 2, QTableWidgetItem(data_list[2]))
		self.tablewidget.setItem(row, 3, QTableWidgetItem(data_list[3]))
		self.tablewidget.setItem(row, 4, QTableWidgetItem(data_list[4]))
		self.tablewidget.setItem(row, 5, QTableWidgetItem(data_list[5]))
		self.tablewidget.setItem(row, 6, QTableWidgetItem(str(data_list[6])))
		
		
		
	def saveData(self):
		path, extension = QFileDialog.getSaveFileName(self, 'Save File', '/newfile.csv', "file (*.csv)")
		if path:
			with open(path, 'w') as stream:
				print("saving", path)
				writer = csv.writer(stream, delimiter='\t')
				headers = []
				for column in range(self.tablewidget.columnCount()):
					header = self.tablewidget.horizontalHeaderItem(column)
					if header is not None:
						 headers.append(header.text())
					else:
						headers.append("Column " + str(column))
				writer.writerow(headers)
				for row in range(self.tablewidget.rowCount()):
					rowdata = []
					for column in range(self.tablewidget.columnCount()):
						item = self.tablewidget.item(row, column)
						if item is not None:
							rowdata.append(item.text())
						else:
							rowdata.append('')
					writer.writerow(rowdata)
					

						
	def opencsv(self):
		count = 0
		path, _ = QFileDialog.getOpenFileName(self, 'Open File', '', "file (*.csv)")
		if path:
			with open(str(path), 'r') as stream:
				self.tablewidget.setRowCount(0)
				self.tablewidget.setColumnCount(0)
				for rowdata in csv.reader(stream):
					
					
					row = self.tablewidget.rowCount()
					self.tablewidget.insertRow(row)
					rowdata = ''.join(rowdata)
					rowdata = rowdata.split('\t')
					
					self.tablewidget.setColumnCount(len(rowdata))
					self.tablewidget.setHorizontalHeaderLabels(['Protocol', 'Protocol Number', 'Source IP', 'Destination IP', 'Source Port', 'Destination port', 'Information'])
					for column, data in enumerate(rowdata):
						item = QTableWidgetItem(data)
						if row:
							self.tablewidget.setItem(row-1, column, item)
					
		
			
		
if __name__ == '__main__':
    isRun = True
    app = QApplication(sys.argv)
    screen = Window()
    screen.show()

    sys.exit(app.exec_())
