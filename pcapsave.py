import time
import struct
import socket
import sniffer





listofraw=[]

def header_size(rawData):
    pcapHeader='d4 c3 b2 a1 02 00 04 00  00 00 00 00 00 00 00 00\
    ff ff 00 00 01 00 00 00'
    pcapHeader=pcapHeader.replace(" ","")
    pcapHeader=bytearray.fromhex(pcapHeader)
    captureTime=time.time()
    second=int(captureTime)
    msecond=int((captureTime-second)*1e6)
    secondByte=struct.pack("I",second)
    msecondByte=struct.pack("I",msecond)
    size=len(rawData)
    sizebyte=struct.pack("I",size)
    return [pcapHeader,secondByte,msecondByte,sizebyte,sizebyte,rawData]
def madepcap(rawData,listofraw):
    captureTime=time.time()
    second=int(captureTime)
    msecond=int((captureTime-second)*1e6)
    secondByte=struct.pack("I",second)
    msecondByte=struct.pack("I",msecond)
    size=len(rawData)
    sizebyte=struct.pack("I",size)
    ls=(secondByte,msecondByte,sizebyte,sizebyte,rawData)
    for i in ls:
        listofraw.append(i)


def writelist(list):
    pcapHeader='d4 c3 b2 a1 02 00 04 00  00 00 00 00 00 00 00 00\
    ff ff 00 00 01 00 00 00'
    pcapHeader=pcapHeader.replace(" ","")
    pcapHeader=bytearray.fromhex(pcapHeader)

    with open("ddd.pcap",'wb') as f:
        f.write(pcapHeader)
        for i in list:
            f.write(i)
    
def writepcap(rawData):
    with open("ddd.pcap",'wb') as f:
        for i in header_size(rawData):
            f.write(i)

#writepcap(raw_data)



def readpcap(address):
    with open(address,'rb') as f:

        f.read(24) #header
        while(True):
            notend=f.read(1)
            if notend: 
                f.read(3)   #second -1
                f.read(4)   #msecond
                f.read(4)   #size
                size=f.read(4)   #size
                size=struct.unpack("I",size)
                rawData=f.read(size[0])
                show=sniffer.sniffer(rawData)
                show.listen_log()
                print("-------------------------------------------------")
            else:
                print("reading file finished")
                break


        

