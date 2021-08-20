import socket
import logging
import time
import datetime as dt
from scapy.all import *

global intface
# configuring the logger for windows and linux
if(sys.platform == "win32"):
    logging.basicConfig(filename="C:\SharedFolder\Monitor.log",level=logging.INFO,
format="%(asctime)s:%(levelname)s:%(message)s")
elif(sys.platform == "linux"):
    import netifaces
    print("It's been found you are on a Linux machine. Kindly type in which interface do you want the sniffer to sniff on.")
    print(netifaces.interfaces())  # outputs a list of interfaces
    intface = input() 
    logging.basicConfig(filename="Monitor.log",level=logging.INFO,
format="%(asctime)s:%(levelname)s:%(message)s")

print("Please refer to Monitor.log for logs")

def ping_request(hostinfo, timeout):        #pings google.com at regular interval
    try:                                    #to check for internet connectivity
        socket.timeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(hostinfo)
    except socket.error as error:
        return False
    else:
        s.close()
        return True

def check_connectivity(check_flag):
    #whether internet connectivity is alive
    if(check_flag is True):
        #print('Connection is alive!')
        logging.info('Connection is alive at '+ str(dt.datetime.now()))
        return True
    else:
        logging.error('lost internet connectivity at ' + str(dt.datetime.now()) + '! Please check your internet connection')
        print("lost internet connectivity!")
        return False

def sniffer():           #sniffs the network traffic
    if(sys.platform == "win32"):
            logging.info(sniff(filter="tcp and port 443", iface="Wi-Fi", prn=lambda x: x.summary()))
    elif(sys.platform == "linux"):
            logging.info(sniff(filter="tcp and port 443", iface=intface, prn=lambda x: x.summary()))

while(True):
    try:
        check_req = ping_request(('www.google.com', 80), 3)
        if(check_connectivity(check_req) is True):
            sniffer()         #sniffing starts
        else:
            time.sleep(3)       # keep retrying to connect after every 3 seconds

    except KeyboardInterrupt as error:
        print('\nexiting...')
        print('Please refer to Monitor.log for logs')
        logging.critical('exiting!')
        exit()
