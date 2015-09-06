#!/usr/bin/env python
#coding=utf-8

import sys
import dpkt
import socket
import binascii

def addr2str(addrobj):
	if len(addrobj) != 4 :
		return "addr error!"
	else:
		return str(ord(addrobj[0]))+"."+str(ord(addrobj[1]))+"."+str(ord(addrobj[2]))+"."+str(ord(addrobj[3]))

def TCPorUDP(obj):
	if (ord(obj) == 0x06):
		return "TCP"
	else:
		return "error"
def main():
　　fw = open("result.txt","w")
　　f = file("./traces_new.cap","rb")
　　pcap = dpkt.pcap.Reader(f)
　　for ts, buf in pcap：
　　　　fw.writelines("timestamp:"+str(ts)+"\tpacket len:"+str(len(buf))+"\n")
　　　　ethheader = buf[0:14]
　　　　dstmac = ethheader[0:6]
　　　　srcmac = ethheader[6:12]
　　　　netlayer_type = ethheader[12:14]
　　　　fw.writelines("dstMAC:"+str(binascii.b2a_hex(dstmac))+"\tsrcMAC:"+str(binascii.b2a_hex(srcmac))+"\n")

　　　　pktheader = buf[14:34]
　　　　trans_type = pktheader[9]
　　　　srcip = pktheader[12:16]
　　　　dstip = pktheader[16:20]

　　　　fw.writelines("dstIP:"+addr2str(dstip)+"\tsrcIP:"+addr2str(srcip)+"\n")
　　　　fw.writelines("packet type:"+TCPorUDP(trans_type)+"\n")

　　　　if (ord(trans_type) == 0x11):	#UDP
　　　　　　udpheader = buf[34:42]
　　　　　　srcport = udpheader[0:2]
　　　　　　dstport = udpheader[2:4]
　　　　　　udplen = udpheader[4:6]
　　　　　　fw.writelines("srcport:"+str(ord(srcport[1])+ord(srcport[0])*16*16)+"\tdstport:"+str(ord(dstport[1])+ord(dstport[0])*16*16)+"\n\n")
　　　　elif (ord(trans_type) == 0x06):	#TCP
　　　　　　tcpheader = buf[34:54]
　　　　　　srcport = tcpheader[0:2]
　　　　　　dstport = tcpheader[2:4]
　　　　　　fw.writelines("srcport:"+str(ord(srcport[1])+ord(srcport[0])*16*16)+"\tdstport:"+str(ord(dstport[1])+ord(dstport[0])*16*16)+"\n\n")
　　f.close()

if __name__ == "__main__":
　　main()