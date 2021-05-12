'''
Script parses PCAP file using the pyshark library.

Reads the client sent timestamps in clienthello random
    IP_SRC        clienthello ts .....

dtls.handshake_type 1 client hello

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
        self.times=[]

    def add_clienthello(self):
        self.clienthello+=1

    def add_helloverify(self):
        self.helloverify += 1

    def add_timestamp(self, ts):
        self.times.append(str(ts)[3:])

    def get_times(self):
        return self.times

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
                        t=p.dtls.handshake_random_time
                        dict[src].add_timestamp(t)
                        t=""
            except:
                pass
        if(pc%100==0):
            print(".", end='')

def save():
    global dict
    f=open("dtls-time-stats.csv","w")
    for i in dict:
        line=str(i)+";"
        for ts in dict[i].get_times():
            line=line+ts+";"
        line=line+"\n"
        f.write(line)
    f.flush()
    f.close()
    print("Saved file dtls-time-stats.csv")

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