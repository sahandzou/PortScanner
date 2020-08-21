import test
import socket
import nmap
import reply
import pcapsave
class sniffer:
    def __init__(self,rawData=None):
        self.raw_data=None
        if(rawData==None):
            self.conn=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
        else:
            self.conn=None
            self.raw_data=rawData
        
        self.addr=None
    def listen_log(self):
        
        self.raw_data,self.addr=self.conn.recvfrom(65535)
        pcapsave.madepcap(self.raw_data,pcapsave.listofraw)
        layer2=test.ehternet(self.raw_data)
        print("Ethernet :")
        print("Source MAC:",layer2.srcMac)
        print("Destination MAC:",layer2.destMac)
        if(layer2.proto==1544):
            opcode,SHA,SPA,THA,TPA,ff,dd,cc=layer2.arp()
            print(f"ARP:\nOPCODE: {opcode}\nSender MAC: {SHA}\nSender IP: {SPA}\nTarget MAC: {THA}\nTarget IP: {TPA}")
            return -1
        layer3=test.ip(layer2.mainData)

        print("IP layer:")

        print("Source IP: ",layer3.sourceIP)
        print("Destination IP:",layer3.desIP)
        




        layer4Protocol=layer3.protocol
        layer2=None
        layer1=None
        if(layer4Protocol==1):  #ICMP
            type1,code,hex,maindatad=layer3.icmp()
            print("type:",type1)
            print("code:",code)
            return
        elif(layer4Protocol==6): #TCP
            print("TCP: ")
            
            layer2=test.tcp(layer3.mainData)
            print("Source port: ",layer2.srcPort)
            print("Destination port: ",layer2.desPort)
        elif(layer4Protocol==17): #UDP
            print("UDP : ")
            layer2=test.udp(layer3.mainData)
            print("Source port: ",layer2.srcPort)
            print("Destination port: ",layer2.desPort)
        else:
            print("This is not our assignmnet we just have TCP , UDP and ICMP:) .|..")
            return -1
        print("Layer 1: ",end="")
        if(layer2.srcPort==80 or layer2.desPort==80):   #HTTP
            print("HTTP")
            
            layer1=test.http(layer2.mainData)
            print(layer1.headers_string)
            #print(layer1.mainData)
        elif(layer2.srcPort==53 or layer2.desPort==53): #DNS
            print("DNS")
            layer1=test.DNS(layer2.mainData)
            print("ID :",layer1.ID)
            print("falgs :",layer1.flags)
            print("Question: ",layer1.question)

        else:
            print("we just have HTTP and DNS")
            return -1
    def listen(self):
        self.raw_data,self.addr=self.conn.recvfrom(65535)
        layer2=test.ehternet(self.raw_data)
        #print(layer2.proto)
        if(layer2.proto==1544):
            opcode,SHA,SPA,THA,TPA,sha,spa,tpa=layer2.arp()
            print(f"ARP:\nOPCODE: {opcode}\nSender MAC: {SHA}\nSender IP: {SPA}\nTarget MAC: {THA}\nTarget IP: {TPA}")
            #print(TPA)
            if('127.0.0.1'==TPA):  #nmap.get_ip_address(b'wlp3s0')
                reply.replyarp(sha,SPA,TPA)

            return -2
        layer3=test.ip(layer2.mainData)

        layer4Protocol=layer3.protocol
        layer2=None
        layer1=None
        if(layer4Protocol==1):  #ICMP
            typeicmp,code,checksum,data=layer3.icmp()
            
            if(typeicmp==8 and code==0 and typeicmp==8):#ping
                id,seq=layer3.ping()
                packet=nmap.packet()
                payload=packet.icmpgenerator(layer3.desIP,layer3.sourceIP,id,seq)
                reply.sendpacket(layer3.sourceIP,payload)
                
                return -3
            return  
        
            
            
            
        elif(layer4Protocol==6): #TCP
            return -1
            layer2=test.tcp(layer3.mainData)
        elif(layer4Protocol==17): #UDP
            #print("udddddddddddddp")
            
            layer2=test.udp(layer3.mainData)
        else:
            return -1
        if(layer2.srcPort==80 or layer2.desPort==80):   #HTTP
            layer1=test.http(layer2.mainData)
            print(layer1.mainData)
        elif(layer2.srcPort==53 or layer2.desPort==53): #DNS
            #layer1=test.DNS(layer2.mainData)
            #print("kkkkkkkkk")
            
            if(layer2.desPort==53 and layer3.desIP=="127.0.0.1"):
                #print("dddddddddddddddddddddd")
                
                reply.dnsreply(layer2.desPort,layer3.sourceIP,layer3.desIP)
                
        else:
            return -1
    def computetcpflag(self):
        #layer2=test.ehternet(self.raw_data)
        #layer3=test.ip(layer2.mainData)
        layer3=test.ip(self.raw_data)
        layer4=test.tcp(layer3.mainData)
        return {"ACK":layer4.flags[4],"RST":layer4.flags[6],"SYN":layer4.flags[7],"FIN":layer4.flags[8],"Port":layer4.desPort,"destPort":layer4.srcPort,"size":layer4.windowSize}

if __name__=="__main__":
    choose=input("sniffer 1 and replyer for part 3 2")
    choose=int(choose)
    test1=sniffer()
    if(choose==2):
        while(True):
            test1.listen()
                
    else:
        for i in range(100):
            test1.listen_log()
        pcapsave.writelist(pcapsave.listofraw)

    
    #test1.listen_log()
