#encoding:utf-8
import sys
import os
import re
import binascii 
class tafContextExtract:

	target_url = ''
	pcapTextFilename = ''
	pcapPath = ''

	def __init__(self,url,pcapPath):
		self.target_url = url
		self.pcapPath = pcapPath
		self.pcapTextFilename = "pcapText.txt"
		self.time = ''
		self.streamid = ''
		self.content = ''
		#print "init sucess"

	def anlyPcap2Text(self):
		os.system('tshark -r'+self.pcapPath+' -Vx > ./pcapText.txt')
		self.pcapTextFilename = "pcapText.txt"
		#print self.pcapPath
		#print "anly pcap to text sucess"

	def hexstr2hex(self,hexstr):
		tmp_hexstr = ''
		items = hexstr.split()
		for chhex in items:
			#print chhex
			tmp_hexstr +=binascii.a2b_hex(chhex)
		return tmp_hexstr

	def getContext(self):
		stream_flag = 0
		request_flag = 0
		response_flag = 0
		begain_flag =   ''
		context = ""
		hexContext =""
		preFrameId = ''
		requestid = ''
		RequestFrameList = []
		unixTime = ''
		f_pcap_txt = open(self.pcapTextFilename)
		requestLen = 0
		responseLen = 0
		try:
			for line in f_pcap_txt:
				line = line.strip()
				#print line
				items = line.split()        #get the length of the packet
				if len(items) > 12 and items[0]=="Frame" and items[3]=="bytes":
					#if len(context) >0:
					#	print preFrameId + str(request_flag) + "\t" + str(begain_flag) + context
					if request_flag==1  and context.find(self.target_url)>=0:
						print "request:\t" + str(unixTime) + "\t" + cur_stream_index + "\t" + context
						self.time = str(unixTime)
						self.streamid = cur_stream_index
						#过滤头部
						hexContext = hexContext.split("0d 0a 0d 0a")[1]
						utf8_str = hexContext.encode("utf-8")
						requestLen = requestLen + len(utf8_str)
						print "hexContext:\t" + self.hexstr2hex(hexContext)
						self.content += self.hexstr2hex(hexContext)
						RequestFrameList.append(preFrameId);
					if response_flag == 1 and requestid!='' and (requestid in RequestFrameList):
						print "response:\t" + str(unixTime) + "\t" + cur_stream_index + "\t" + context
						#过滤头部
						hexContext = hexContext.split("0d 0a 0d 0a")[1]
						utf8_str = hexContext.encode("utf-8")
						responseLen = responseLen + len(utf8_str)
						print "hexContext:\t" + self.hexstr2hex(hexContext)
					preFrameId = items[1][:-1]
					cur_len = int(preFrameId)
					cur_stream_index = ''
					request_flag = 0
					response_flag = 0
					begain_flag = 0
					context = ""
					hexContext = ""
					requestid = ''
					continue

				if line.find("HTTP response")>=0:
					response_flag = 1
					continue

				if line.find("HTTP request")>=0:
					request_flag = 1

					continue

				if (request_flag == 1 or response_flag ==1) and line.find("Reassembled TCP")>=0:
					begain_flag = 1
					context = ""
					hexContext = ""
					continue
        	
				if response_flag == 1 and line.find("Request in frame:") >=0:
					requestid = items[-1][:-1]
					#print "requestid" +requestid


				if len(items) == 3 and items[0] == "[Stream":
					#print "aaaaaaaaa" + line
					cur_stream_index = items[2][:-1] 

				if line.find("Epoch Time") >=0:
					unixTime = int(float(items[2]))
				if begain_flag == 1:
					tmp = re.search('^[0-9a-f]{4}\s\s[0-9a-f]{2}',line)
					if tmp:
						context = context + ''.join(line.split("   ")[-1]);
						hexContext = hexContext + " " + line.split("  ")[1];
				elif response_flag ==1 or request_flag == 1:
					tmp = re.search('^[0-9a-f]{4}\s\s[0-9a-f]{2}',line)
					if tmp:
						context = context + ''.join(line.split("   ")[-1]);
						hexContext = hexContext + " " + line.split("  ")[1];
			f_pcap_txt.close()
			print "++++++++++++:" + str(requestLen) + " " + str(responseLen)
		except:
			print "something error!"



#tafExtractor = tafContextExtract("newsso.map.qq.com:8080","Capture20150729180611_1.pcap")
#tafExtractor = tafContextExtract("navsns.3g.qq.com","s_o_n.pcap")
tafExtractor = tafContextExtract("CMD_ROUTE","Capture1_2.pcap")
tafExtractor.anlyPcap2Text()
tafExtractor.getContext()
