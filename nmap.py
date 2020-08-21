import socket
import time
import threading
import struct
import random
import fcntl
import sniffer
import sys
import getopt
import PORTS


def ConnectScan(address="",period=(0,100),delay=0):
    

    try: 
        host_ip = socket.gethostbyname(address) 
        print(host_ip)
    except socket.gaierror: 
        print ("there was an error resolving the host")
        return -1
    openPorts={"open":[],"closed":[],"filterd":[],"unfilterd":[]}
    for port in range(period[0],period[1]+1):
        threading.Thread(target=connectScanCheck, args=(address,port,openPorts)).start()
        time.sleep(delay)
        #print("count:",threading.active_count())
        while(threading.active_count()>200):
            pass
    while(threading.active_count()>1):
        time.sleep(0.2)
    return openPorts
        
def connectScanCheck(address,port,openPorts):
        try: 
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
            s.settimeout(1)
        except socket.error as err: 
            print("Socket creation error %s" %(err))
            return -1
        #print(port)
        result=s.connect_ex((address,port))
        if(result==0):
            openPorts['open'].append(port)
    


class packet:
    def __init__(self):
        pass
    def makeippacket(self,srcIP,destIP,protocol=6):
        version=4
        ihl=5
        tts=0
        len=0x28 #:(
        id=random.randint(1,35214)
        id=35000
        flags=0
        offset=0
        ttl=64
        self.protocol=protocol
        checksum=0
        self.srcip=socket.inet_aton(srcIP)
        self.destIP=socket.inet_aton(destIP)
        firstbyte=(version<<4)+ihl
        forthbyte=flags<<13+offset
        packet_tmp=struct.pack("!BBHHHBBH4s4s",firstbyte,tts,len,id,forthbyte,\
            ttl,self.protocol,checksum,self.srcip,self.destIP)
        packet=struct.pack("!BBHHHBBH4s4s",firstbyte,tts,len,id,forthbyte,\
            ttl,self.protocol,self.checksum(packet_tmp),self.srcip,self.destIP)
        return packet,packet_tmp

    def maketcpsegment(self,srcPort,destPort,ACK,SYN,FIN,RST,packet):
        srcPort=srcPort
        destPort=destPort
        seqnumber=12345
        acknumber=0
        offset=5
        window=8192
        reserved=0
        urgent=0
        option=None
        padding=None
        data=None
        checksum=0
        PSH=0
        URG=0
        flags=((FIN)|(SYN<<1)|(RST<<2)|(PSH<<3)|(ACK<<4)|(URG<<5))
        flagsoffset=(offset<<12)|(reserved<<6)|(flags)
        #print(flagsoffset)
        segmenttmp=struct.pack("!HHLLHHHH",srcPort,destPort,seqnumber,\
            acknumber,flagsoffset,window,checksum,urgent)
        pseudotcpheader=struct.pack("!4s4sBBH",self.srcip,self.destIP,0,self.protocol,len(packet))
        compute=pseudotcpheader+segmenttmp
        segment=struct.pack("!HHLLHHHH",srcPort,destPort,seqnumber,\
            acknumber,flagsoffset,window,self.checksum(compute),urgent)
        '''segment=struct.pack("!HHLLHHHH",srcPort,destPort,seqnumber,\
            acknumber,flagsoffset,window,self.checksum(segment),urgent)   '''        #0xac03
        return segment
    def udppacket(self,src_ip, dst_ip, src_port, dst_port, data):
        source_port = src_port
        dest_port = dst_port
        length = 8 + 4
        data = 0
        udp_checksum = 0
        source_ip = socket.inet_aton(src_ip)
        dest_ip = socket.inet_aton(dst_ip)
        protocol = 17
        udp_header = struct.pack('!HHHH', source_port, dest_port, length, udp_checksum)
        place_holder = 0
        temp_header = struct.pack('!4s4sBBH', source_ip, dest_ip, place_holder,
                                protocol, len(udp_header))
        temp_header = temp_header + udp_header
        udp_checksum = self.checksum(temp_header)
        #print(temp_header)

        segment = struct.pack('!HHHHL', source_port, dest_port, length, udp_checksum, data)
        return segment
    def checksum(self,packet):
        checksum=0
        for i in range(0,len(packet),2):
            checksum+=(packet[i]<<8)+packet[i+1]
            #if(checksum&(1<<16)):
            #    tmp=(checksum&0xFFFF)+1
        checksum=(checksum>>16)+(checksum&0xffff)
        checksum=checksum&0xFFFF
        checksum=checksum^0xFFFF
        #print(checksum)
        #print("---------------------")
        return checksum
    def generate(self,srcIP,destIP,srcPort,destPort,ACK,SYN,FIN,RST):
        packet,packettmp=self.makeippacket(srcIP,destIP)
        segment=self.maketcpsegment(srcPort,destPort,ACK,SYN,FIN,RST,packet)
        return packet+segment
    def icmpgenerator(self,srcIP,destIP,id,seq):
        packet,packettmp=self.makeippacket(srcIP,destIP)
        messageType=0
        code=0
        tmp_header=struct.pack("!BBHHH",messageType,code,0,id,seq)
        checksum=self.checksum(tmp_header)
        message=b"im ok"
        header=struct.pack("!BBHHH6s",messageType,code,checksum,id,seq,message)
        packet=self.makeippacket(srcIP,destIP,1)
        packet=packet[0]+header
        

        return packet
        

    

def sendpacketraw(destIP,srcPort,destPort,attack):
    payloadpacket=packet()
    myip=get_ip_address(b'wlp3s0')
    payload=None
    if(attack==1):
        payload=payloadpacket.generate(myip,destIP,srcPort,destPort,1,0,0,0) #ack
    elif(attack==2):
        payload=payloadpacket.generate(myip,destIP,srcPort,destPort,0,1,0,0) #syn
    elif(attack==3):
        payload=payloadpacket.generate(myip,destIP,srcPort,destPort,0,0,1,0) #fin
    else:
        payload=payloadpacket.generate(myip,destIP,srcPort,destPort,1,0,0,0)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.sendto(payload,(destIP,0))
    return
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915, 
        struct.pack('256s', ifname[:15])
    )[20:24])


CONNECT_ATTACK=0
ACK_ATTACK=1
SYN_ATTACK=2
FIN_ATTACK=3
WIN_ATTACK=4

def attack(address="",period=(0,100),delay=0,attack=0):
    openports=[]
    openports={"open":[],"closed":[],"filterd":[],"unfilterd":[]}
    if(attack==0):
        
        openports=ConnectScan(address,period,delay)
    else:
        host_ip=None
        try: 
            host_ip = socket.gethostbyname(address) 
            print(host_ip)
        except socket.gaierror: 
            print ("there was an error resolving the host")
            return -1
        threading.Thread(target=receiver,args=(attack,12345,openports)).start()
        for port in range(period[0],period[1]+1):
            #print("scanning port:",port)
            sendpacketraw(host_ip,12345,port,attack)
            time.sleep(delay)
    time.sleep(2.5)
    threading.Thread()._stop()
    openports["open"].sort()
    openports['filterd'].sort()
    openports['closed'].sort()
    openports['unfilterd'].sort()
    #print(openports)
    return openports
def ui(data,kind):
    print('PORT         STATUS          SERVICE')
    for i in data[kind]:
        try:
            PORTS.services[str(i)]
            print(f"{i}         {kind}          {PORTS.services[str(i)]}")
        except:
            print(f"{i}         {kind}          None")


        
    print("----------------------------------------------")
def receiver(attack,port,ports):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    while(True):
        data=s.recvfrom(1024)
        try:
            portscan=sniffer.sniffer(data[0])
            data=portscan.computetcpflag()
            if(data["Port"]!=12345):
                return
            else:
                #print(data["Port"])
                pass
            if(attack==1):
                if(data["RST"]==1):
                    ports['unfilterd'].append(data["destPort"])
            elif(attack==2):
                if(data["ACK"]==1 and data["SYN"]==1):
                    #ports.append(data["destPort"])
                    ports["open"].append(data["destPort"])
                elif(data["RST"]==1):
                    ports["closed"].append(data["destPort"])
                else:
                    ports["filterd"].append(data["destPort"])
            
            elif(attack==3):
                if(data["RST"]==1):
                    ports['closed'].append(data["destPort"])
            elif(attack==4):
                if(data["RST"]==1 and data["size"]>0):
                    ports['open'].append(data["destPort"])
                elif(data["RST"]==1 and data["size"]==0):
                    ports['closed'].append(data["destPort"])
                else:
                    ports['filtered'].append(data["destPort"])

                
                
        except:
            pass

def handler():
    pass


if __name__=="__main__":

    portrange=None
    address=None
    attack1=None
    argv=sys.argv[1:]
    delayd=0
    
    opts, args = getopt.getopt(argv,"p:t:s:d:")
    for opt,arg in opts:
        if(opt=="-p"):
            portrange=arg.split("-")
            portrange[0]=int(portrange[0])
            portrange[1]=int(portrange[1])

        elif(opt=="-t"):
            address=arg
        elif(opt=="-s"):
            if(arg=="s"):
                attack1=SYN_ATTACK
            elif(arg=="a"):
                attack1=ACK_ATTACK
            elif(arg=="c"):
                attack1=CONNECT_ATTACK
            elif(arg=="f"):
                attack1=FIN_ATTACK
            elif(arg=="w"):
                attack1=WIN_ATTACK
        elif(opt=="-d"):
            delayd=int(arg)

    hack=attack(address,attack=attack1,period=portrange,delay=delayd)
    if(attack1==SYN_ATTACK):
        ui(hack,'open')
        ui(hack,'closed')
        ui(hack,'filterd')
    elif(attack1==ACK_ATTACK):
        ui(hack,'unfilterd')
    elif(attack1==CONNECT_ATTACK):
        ui(hack,'open')
    elif(attack1==FIN_ATTACK):
        ui(hack,'closed')
    elif(attack1==WIN_ATTACK):
        ui(hack,'open')



    
                  

    



        
