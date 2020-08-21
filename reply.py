import nmap
import struct
import socket
import sniffer
import nmap
from getmac import get_mac_address as gma
def sendpacket(destIP,payload):
    myip=nmap.get_ip_address(b'wlp3s0')
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.sendto(payload,(destIP,0))
    s.close()
def replyarp(tha,tpa,spa):
    HTYPE=1
    PTYPE=128
    HLEN=6
    PLEN=4
    opcode=2
    #SHA=gma()
    SHA=bytearray.fromhex('000a959d6816')
    #SPA=socket.inet_aton(nmap.get_ip_address(b'wlp3s0'))
    SPA=socket.inet_aton(spa)
    #print(SPA)
    THA=tha
    TPA=socket.inet_aton(tpa)

    header=struct.pack("!HHBBH6s4s6s4s",HTYPE,PTYPE,HLEN,PLEN,opcode,SHA,SPA,THA,TPA)
    ehternet=struct.pack("!6s6sH",tha,SHA,0x806)
    #data="28 c6 3f ad 26 31 1c 5f 2b 30 3c b8 08 06 00 01 08 00 06 04 00 02 1c 5f 2b 30 3c b8 c0 a8 01 01 28 c6 3f ad 26 31 c0 a8 01 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    #data=bytearray.fromhex(data)
    data=ehternet+header
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
    sock.bind(('lo', socket.SOCK_RAW))
    sock.send(data)

    print("sent")
def dnsreply(port,srcip,destip):
    packet=nmap.packet()
    dnsdata=" 23 7b 81 80 00 0 100 01 00 00 00 01 04 6d 61 69 6c 03 69 75 74 02 61 63 02 69 72 00 00 01 00 01 c0 0c 00 01 00 01 00 00 07 75 00 04 b0 65 34 46 00 00 29 ff d6 00 00 00 00 00 00  "
    dnsdata="75 62 75 6e 74 75 03 63 6f 6d 00 00 1c 00 01 00  00 29 ff d6 00 00 00 00 00 00    "
    dnsdata=dnsdata.replace(" ","")
    dnsdata=bytearray.fromhex(dnsdata)
    pack=packet.udppacket(destip,srcip,53,port,dnsdata)
    packet1,packettmp=packet.makeippacket(srcip,destip)
    #print(pack)
    pack=packet1+pack+dnsdata
    sendpacket(srcip,pack)
    print(srcip)
if __name__=="__main__":
    test=nmap.packet()

    myip=nmap.get_ip_address(b'wlp3s0')
    destIP="192.168.1.1"
    packet=test.icmpgenerator(myip,destIP)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    print(type(packet))
    s.sendto(packet,(destIP,0))
    s.sendto(packet,(destIP,0))
    s.close



