from socket import *
from urlparse import urljoin
import thread
import urllib, urllib2
import os
import re
import threading 
import json
import time
import requests

IP_MTU_DISCOVER   = 10
IP_PMTUDISC_DONT  =  0  # Never send DF frames.
IP_PMTUDISC_WANT  =  1  # Use per route hints.
IP_PMTUDISC_DO    =  2  # Always DF.
IP_PMTUDISC_PROBE =  3  # Ignore dst pmtu.

class ThreadedServer(object):
	def __init__(self, host, port):
		self.serverPort = port
		self.serverHost = host
		self.serverSocket = socket(AF_INET, SOCK_STREAM)
		self.serverSocket.setsockopt(SOL_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT)
		#self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.serverSocket.bind((self.serverHost, self.serverPort))
		self.cachePath = "./cache/"
		self.size = 2048
		self.jsonPath = './metadata/contentType.json'
		self.jsonFile = ''
		self.extDict  = {}
		self.TTL = 60
		if not os.path.isdir(self.cachePath):
			os.makedirs(self.cachePath)
		if not os.path.isfile(self.jsonPath):
			if not os.path.isdir('./metadata/'):
				os.makedirs('./metadata/')
			with open(self.jsonPath, 'w+') as self.jsonFile:
				json.dump({}, self.jsonFile)

	def listen(self):
	 	self.serverSocket.listen(5)
		with open(self.jsonPath, 'r+') as self.jsonFile:
			self.extDict = json.load(self.jsonFile)
		jsonCnt=0
		while True:
			connectionSocket, addr = self.serverSocket.accept()
			connectionSocket.settimeout(60)
			threading.Thread(target = self.listenToClient,args = (connectionSocket,addr)).start()
			if jsonCnt==5:
				os.remove(self.jsonPath)	
				with open(self.jsonPath, 'w') as self.jsonFile:
					json.dump(self.extDict, self.jsonFile, indent=8)
				jsonCnt=0
			jsonCnt+=1


	def listenToClient(self, connectionSocket, addr):
		try:
			message = connectionSocket.recv(2048)
			msg = message.decode()
			httpsIndex = msg.find('443')
			
			#Return for https
			if httpsIndex !=-1:
				connectionSocket.close()
				return


			print "*********************************************************"
			print msg
			first = msg.find('GET')+4
			httpIndex = msg.find('http')
			last  = msg.find('HTTP', first+1)-1
			url   = str(msg[first: last])

			#Return for empty urls
			if not url:
				connectionSocket.close()
				return

			host  = ''
			hostIndex1 = msg.find('Host', last+1)
			hostIndex2 = -1
			if hostIndex1!=-1 and httpIndex==-1:
				hostIndex1 = msg.find(' ' , hostIndex1)+1
				hostIndex2 = msg.find('\n', hostIndex1)
				host = str(msg[hostIndex1: hostIndex2])
				host = host.strip('\r')
				host = host.strip('\n')
			if httpIndex==-1:
				host='http://'+host
			url = host+''+url
			reqType = ''
			print "url:", url

			if (not url) or first==-1:
				#continue
				return
			else:
				firstType = msg.find('Accept: ')
				lastType  = msg.find('\r\n',firstType)
				reqType   = msg[firstType+8: lastType]
				#print reqType	
				urlFile = re.sub('[^A-Za-z0-9_\\.]','-',url)
				
				#On demand stale data check
				if url in self.extDict:
					currentTime = time.time()
					if currentTime - self.extDict[url][1] > self.extDict[url][2]:
						#conditional get
						headResp = requests.head(url)
						if headResp.headers['Last-Modified']!=self.extDict[url][3]:
							print 'CACHE DATA IS STALE - DELETING FROM CACHE'
							del self.extDict[url]
							os.remove(self.cachePath+urlFile)
						else:
							print 'CACHE DATA IS STILL VALID - LAST MODIFIED IS SAME IN CONDITIONAL GET'
							self.extDict[url][1] = currentTime
				
				if url not in self.extDict:
					print 'GETTING FROM NET'
					f = open(self.cachePath+urlFile, 'w+')
					try:
						fileName = urllib2.urlopen(url)
						self.extDict[url] = [fileName.info().getheader('Content-Type'), time.time(), self.TTL, fileName.info().getheader('Last-Modified')]
						chunk = fileName.read(self.size)
						while chunk:
							f.write(chunk)
							chunk = fileName.read(self.size)
						f.close()
						#urllib.urlretrieve(url, urlFile) 
					except urllib2.HTTPError:
						return
				else:
					print 'GETTING FROM CACHE'
				f = open(self.cachePath+urlFile, 'rb')
				html = f.read(self.size)
				print "*********************************************************"
				print "\n\n\n"
				#print 'url', url
				connectionSocket.send("HTTP/1.1 200 OK\r\n"+
				"Content-Type: "+self.extDict[url][0]+"\r\n"+
				"\r\n")
		
				while html:
					#print html
					connectionSocket.send(html)
					html = f.read(self.size)
				f.close()
				connectionSocket.close()
		except KeyboardInterrupt:
			with open(self.jsonPath, 'r+') as self.jsonFile:
					json.dump(self.extDict, self.jsonFile, indent=8)
			connectionSocket.close()
		finally:
			with open(self.jsonPath, 'w') as self.jsonFile:
					json.dump(self.extDict, self.jsonFile, indent=8)
			connectionSocket.close()

if __name__ == "__main__":
	#port_num = input("Port? ")
	port_num = 80
	ThreadedServer('',port_num).listen()
