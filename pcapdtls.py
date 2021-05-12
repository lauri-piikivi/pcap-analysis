'''
Script parses PCAP file using the pyshark library.

Script counts the occurances of DTLS  messages for IP6 addresses
    IP_SRC   IP_DST     clienthello 2
                        alert 0
                        application_data 45

It is easy to find devices that have problems in DTLS handshake

ASSUMPTION is that CID packets go to server, normal applicaiton  packets to device

dtls.handshake_type 1 client hello
                    2 server hello
                    3 hello verify
dtls.record.content_type 21 Alert
dtls.record.content_type 23 application data
dtls.record.special_type == 25  CID (to server)
'''

import pyshark
import sys

class info:

    def __init__(self, src, dst):
        self.src=src
        self.dst=dst
        self.clienthello = 0
        self.helloverify = 0
        self.serverhello = 0
        self.alert = 0
        self.appdata = 0
        self.server=""

    def add_clienthello(self):
        self.clienthello+=1

    #int os overridden to clienhello count, used in sorting
    def __int__(self):
        return int(self.clienthello)

    def __lt__(self, o):
        return self.clienthello < int(o)

    def add_helloverify(self):
        self.helloverify += 1

    def add_serverhello(self):
        self.serverhello += 1

    def add_alert(self):
        self.alert += 1

    def add_appdata(self):
        self.appdata += 1


    def __str__(self):
        return str(self.src)+" --> "+str(self.dst)+"; ch hv sh app alert;"+str(self.clienthello)+";"+str(self.helloverify)+";"+str(self.serverhello)+";"+str(self.appdata)+";"+str(self.alert)+"\n"

dict={}

#get addresses of packet, reverse the source and destination for incoming packets
def get_addr(p, switched=False):
    src = p.ipv6.src
    dst = p.ipv6.dst
    if not switched:
        return src, dst
    else:
        return dst, src

#check if disctionary has the src key, if not, create it
def check_or_create(src, dst):
    global dict
    if src in dict:
        return
    else:
        inf = info(src, dst)
        dict[src] = inf

def process(cap):
    global dict
    #step packets
    pc=0
    for p in cap:
        pc+=1
        if 'dtls' in p:
            try:
                #client hello
                if int(p.dtls.record_epoch) == 0:
                    if int(p.dtls.handshake_type) == 1:
                        src, dst=get_addr(p)
                        check_or_create(src, dst)
                        dict[src].add_clienthello()
                    #server hello, dst and src are switched
                    if int(p.dtls.handshake_type) == 2:
                        src, dst=get_addr(p, switched=True)
                        dict[src].add_serverhello()
                        cert=p.dtls.x509if_relativedistinguishedname_item_element
                        dict[src].add_servercert(cert)
                    #hello verify, dst and src are switched
                    if int(p.dtls.handshake_type) == 3:
                        src, dst=get_addr(p, switched=True)
                        check_or_create(src, dst)
                        dict[src].add_helloverify()
                # dtls.record.content_type 21 Alert
                if int(p.dtls.record_content_type) == 21:
                    src, dst = get_addr(p, switched=True)
                    check_or_create(src, dst)
                    dict[src].add_alert()
                #dtls.record.content_type 23 application data
                if int(p.dtls.record_content_type) == 23:
                    src, dst = get_addr(p, switched=True)
                    check_or_create(src, dst)
                    dict[src].add_appdata()
                #dtls.record.special_type == 25 CID (to server)
                if int(p.dtls.record_content_type) == 25:
                    src, dst = get_addr(p, switched=False)
                    check_or_create(src, dst)
                    dict[src].add_appdata()
            except:
                pass
        if(pc%100==0):
            print(".", end='')

def save():
    global dict
    f=open("dtls-stats.csv","w")
    print("TOP adresses by clienthello count")
    print("from-->to; clienthello count, helloverify count, serverhello count, app data, alerts")

    tt=0
    for i in sorted(dict, key=dict.get, reverse=True):
        f.write(str(dict[i]))
        if tt < 10:
            print("TOP ",tt," ",dict[i], end ="")
        tt+=1
    f.flush()
    f.close()
    print("\nSaved file dtls-stats.csv")

def main(file):
    cap = pyshark.FileCapture(file)
    process(cap)
    save()
    print("DONE")

if __name__ == '__main__':
    args=sys.argv
    if len(args)<2:
        print("Must give PCAP file to analyse")
        sys.exit(1)
    else:
        print("Start analyse "+args[1])
        main(args[1])