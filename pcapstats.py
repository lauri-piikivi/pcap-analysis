'''
Script parses PCAP file using the pyshark library.

'''
import pyshark
import sys

dict={}

def process(cap):
    global dict
    #step packets
    pc=0
    for p in cap:
        pc+=1
        l=p.layers
        num=0
        if str(l) in dict:
            num=dict[str(l)]
        else:
            print("\n", str(l), end='')
        num+=1
        dict[str(l)]=num

        if(pc%1000==0):
            print(".", end='')
    print("\nPacket count total is ",pc)

def print_dict():
    global dict
    print("PACKET Layers and the counts is")
    for k,v in sorted(dict.items()):
        print(k,v)

def main(file):
    cap = pyshark.FileCapture(file)
    process(cap)
    print_dict()
    print("DONE")

if __name__ == '__main__':
    args=sys.argv
    if len(args)<2:
        print("Must give PCAP file to analyse")
        sys.exit(1)
    else:
        print("Start analyse "+args[1])
        main(args[1])