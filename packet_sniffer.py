import socket
from struct import *
import pcapy

def eth_addr(a):
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0] , a[1] , a[2], a[3], a[4] , a[5])
	return b
def parsePacket():
	(header, packet) = cap.next()
	# Ethernet header
	eth_header = packet[:14]
	eth = unpack('!6s6sH', eth_header)
        
	eth_proto = socket.ntohs(eth[2])
	source_mac = eth_addr(packet[6:12])
	dest_mac = eth_addr(packet[0:6])
	
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
        
		s_addr = socket.inet_ntoa(iph[8])   # Coverts 32 bit string to dotted quad format
		d_addr = socket.inet_ntoa(iph[9])
		if protocol == 17:
			#print('UDP')
			packet = packet[14+iph_length: 14+iph_length+8]
			header = unpack('!HHHH', packet)
			source_port = header[0]
			dest_port = header[1]
			print('Ethernet Frame: ')
			print(' - Source MAC: ', source_mac, 'Destination MAC: ', dest_mac)
			print('\t IPv4 Packet:')
			print('\t - Version: ', version, ',Protocol: ', protocol, ',Source address: ', s_addr, ',Destination address: ', d_addr) 
			print('\t\t -', 'UDP Segment: ')
			print('\t\t\t -', 'Source Port: ', source_port, ',Destination port: ', dest_port)
			print('-' * 50)
               
		elif protocol == 6: 
			
			t = 14 + iph_length
			packet = packet[t: t+20]
			tcph = unpack('!HHLLBBHHH', packet)
			source_port = tcph[0]
			dest_port = tcph[1]
			seq = tcph[2]
			ack = tcph[3]
			h_size = iph_length +(tcph[4] >> 4) * 4
			data_size = len(packet) - h_size
			print('Ethernet Frame: ')
			print('Source MAC: ', source_mac, 'Destination MAC: ', dest_mac, 'Protocol: ', eth_proto)
			print('\t IPv4 Packet:')
			print('\t - Version: ', version, ',Protocol: ', protocol, ',Source address: ', s_addr, ',Destination address: ', d_addr) 
			print('\t\t -', 'TCP Segment: ')
			print('\t\t\t -', 'Source Port: ', source_port, ',Destination port: ', dest_port)
			print('\t\t\t -', 'Sequence: ', seq, ',Acknowledgement: ', ack)
			#print('\t\t\t -', 'Data: ', packet[h_size:])
			print('-' * 50)
			
		elif protocol == 1:
			#print('ICMP')
			t = 14 + iph_length
			packet = packet[t: t+4]
			icmph = unpack('!BBH', packet)
			print('Ethernet Frame: ')
			print('Source MAC: ', source_mac, 'Destination MAC: ', dest_mac)
			print('\t IPv4 Packet:')
			print('\t - Version: ', version, ',Protocol: ', protocol, ',Source address: ', s_addr, ',Destination address: ', d_addr) 
			print('\t\t -', 'ICMP Segment: ')
			print('\t\t\t Type: ', icmph[0], ',Code: ', icmph[1])
			print('-'*50)
	
	
if __name__ == '__main__':
	devices = pcapy.findalldevs()
	for d in devices:
		print(d)
	dev = input('Enter device name: ')
	
	cap = pcapy.open_live(dev, 65536, 1, 0)
	print('Sniffing', dev, ':')
	while True:
		
			parsePacket()
		
	
	
	
