import socket
import struct
import re
#print("address tuple",addr)
#print("raw Data",raw_data)

#-----------------------------------------Ethernet-----------------

class ehternet:
    def __init__(self,raw):
        self.raw=raw
        self.destMac=None
        self.srcMac=None
        self.proto=None
        self.header=struct.unpack("!6s6sH",raw[:14])
        #print(self.get_mac(self.header[0]))
        self.proto=socket.ntohs(self.header[2])
        self.destMac=self.get_mac(self.header[0])
        self.srcMac=self.get_mac(self.header[1])
        self.mainData=raw[14:]

    def get_mac(self,byte):
        rawHex=byte.hex()
        #print(rawHex) we can decide what kind of output we want
        rawHex=rawHex[0:2]+":"+rawHex[2:4]+":"+rawHex[4:6]+":"+\
                rawHex[6:8]+":"+rawHex[8:10]+":"+rawHex[10:12]
        return rawHex
    def arp(self):          #0x0806 1544
        header=struct.unpack("!HHBBH6s4s6s4s",self.mainData[:28])
        HTYPE=header[0]
        PTYPE=hex(header[1])
        HLEN=header[2]
        PLEN=header[3]
        opcode=header[4]
        SHA=self.get_mac(header[5])
        SPA=socket.inet_ntoa(header[6])
        THA=self.get_mac(header[7])
        TPA=socket.inet_ntoa(header[8])
        #print(f"SHA:{SHA}SPA:{SPA},THA:{THA},TPA:{TPA}")
        return [opcode,SHA,SPA,THA,TPA,header[5],header[6],header[8]]


            
#--------------------------------------------IP------------------------------
class ip:
    def __init__(self,data):
        self.header=struct.unpack("!BBHHHBBH4s4s",data[:20])
        self.version=self.header[0]>>4
        self.IHL=(self.header[0]& 0xF)*4
        self.DSCP=self.header[1]
        self.length=self.header[2]
        self.ID=self.header[3]
        self.flag=self.header[4]>>13
        self.offset=self.header[4]& 0x1FFF
        self.TTL=self.header[5]
        self.protocol=self.header[6]
        self.checksum=hex(self.header[7])
        self.sourceIP=socket.inet_ntoa(self.header[8])
        self.desIP=socket.inet_ntoa(self.header[9])
        self.mainData=data[(self.header[0]&0xF)*4:]
        if(self.protocol==1):
            self.icmp()
        
    def icmp(self):
        type,code,checksum=struct.unpack("!BBH",self.mainData[:4])
        #print("icmp type is:",type)
        #print("icmp code is:",code)
        return [type,code,hex(checksum),self.mainData[4:]]
    def ping(self):
        type,code,checksum,id,seq=struct.unpack("!BBHHH",self.mainData[:8])
        return [id,seq]


#--------------------------------------------TCP--------------------------
class tcp:
    def __init__(self,data):
        self.header=struct.unpack("!HHLLHHHH",data[:20])
        self.srcPort=self.header[0]
        self.desPort=self.header[1]
        self.sequence=self.header[2]
        self.ack=self.header[3]
        flags=self.header[4]
        self.windowSize=self.header[5]
        self.checksum=hex(self.header[6])
        self.urgPtr=self.header[7]
        offset=(flags>>12)*4
        reserved=((flags>>9) & (0x07))
        NS=((flags>>8)& (0x01))
        CWR=((flags>>7)& (0x01))
        ECE=((flags>>6)& (0x01))
        URG=((flags>>5)& (0x01))
        ACK=((flags>>4)& (0x01))
        PSH=((flags>>3)& (0x01))
        RST=((flags>>2)& (0x01))
        SYN=((flags>>1)& (0x01))
        FYN=((flags)& (0x01))
        self.flags=[NS,CWR,ECE,URG,ACK,PSH,RST,SYN,FYN]
        #print(self.flags)
        self.mainData=data[offset:]
##-------------------------------------UDP---------------------------------
class udp:
    def __init__(self,data):
        self.header=struct.unpack("!HHHH",data[:8])
        self.srcPort=self.header[0]
        self.desPort=self.header[1]
        self.len=self.header[2]
        self.checksum=hex(self.header[3])    
        self.mainData=data[8:]
#----------------------------------------http--------------------------------
class http:
    def __init__(self,data):
        self.mainData = None
        self.headers_string=None
        try:
            self.mainData = data.decode("utf-8")
            self.get_headers(self.mainData)
        except:
            self.mainData = data

    def get_headers(self, data):
        d = re.split("\r\n\r\n", data)
        headers = re.split("\r\n", d[0])
        self.headers = {}
        if "HTTP" in headers[0]:
            for h in headers[1:]:
                r = re.split(": ", h)
                self.headers[r[0]] = r[1]
            self.headers_string = d[0]

class DNS:
    def __init__(self,data):
        self.header=struct.unpack("!HHHHHH",data[:12])
        self.ID=hex(self.header[0])
        self.flags=hex(self.header[1])
        self.question=self.header[2]
        self.answer=self.header[3]
        self.authority=self.header[4]
        self.additional=self.header[5]
        self.mainData=data[12:]

        
if __name__=="__main__":
        
    conn=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
    raw_data,addr=conn.recvfrom(65535)

                
    test=ehternet(raw_data)

    print("source MAC address:",test.srcMac)

    ip=ip(test.mainData)
    print("IP protocol number:",ip.protocol)
    tcp=tcp(ip.mainData)
    print("tcp destination source:",tcp.desPort)
    print("ip source",ip.sourceIP)
    print("ip destination",ip.desIP)
    print("sequence: ",tcp.sequence)
    print("source ack: ",tcp.ack)
    http=http(tcp.mainData)
    print("http Data: ",http.mainData)

    '''
            

    dest_mac,src_mac,proto=struct.unpack("! 6s 6s H",raw_data[:14])

    print(dest_mac.hex())
    string=dest_mac.hex()
    print(bytearray.fromhex(string))
    '''