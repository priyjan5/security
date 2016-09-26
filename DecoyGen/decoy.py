import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import optparse
import random
from scapy.all import sr1 ,  IP , ICMP , TCP , send

def SYNPacketConstructor(srcAddr , dstAddr , dstPort):
    ip = IP(src=srcAddr , dst=dstAddr)
    srcPort = random.randint(30000 , 60000)
    SYN = TCP(sport= srcPort, dport=dstPort , flags='S' , seq=1000)
    p = ip / SYN
    send(p)
    ACK = TCP(sport= dstPort, dport=srcPort, flags='A')
    p = ip / ACK
    send(p)


def XMASPacketConstructor(srcAddr , dstAddr , dstPort):
    ip = IP(src=srcAddr , dst=dstAddr)
    srcPort = random.randint(30000 , 60000)
    ACK = TCP(sport= dstPort, dport=srcPort, flags=random.choice(['A' , 'U' , 'R' , 'F'])+random.choice(['A' , 'U' , 'R' , 'F' , 'P']) , ack=60)
    p = ip / ACK
    send(p)


def ICMPPacketConstructor(srcAddr , dstAddr , dstPort):
    ip = IP(src=srcAddr , dst=dstAddr) / ICMP()
    send(ip)

def getRandIP(IPPool):
    finalAddr = ""
    sample = IPPool.split(".")
    for octet in sample:
        if octet =='xx':
            finalAddr += str(random.randint(1,254))
        else:
            finalAddr += octet
        finalAddr += "."
    finalAddr = finalAddr[0:len(finalAddr) - 1]
    return finalAddr


def scanSimulator(srcAddr , dstAddr):
    srcSample = srcAddr.split(".")
    dstSample = dstAddr.split(".")

    while True:
        finalSrcAddr = getRandIP(srcAddr)
        finalDstAddr = getRandIP(dstAddr)

        SYNPacketConstructor(finalSrcAddr , finalDstAddr , random.choice([21 , 22 , 25 , 80 , 443 , 445 , 111 , 139 , 666 , 31337]))
        i = random.randint(0 , 1)
        if i:
            ICMPPacketConstructor(finalSrcAddr , finalDstAddr , random.randint(20,1024))
        else:
            XMASPacketConstructor(finalSrcAddr , finalDstAddr , random.randint(20,1024))



def main():
    parser = optparse.OptionParser("Usage: TDB later")
    parser.add_option('-S', dest='srcAddr', type='string', help='specify spoofed address. i.e 192.168.xx.xx ')
    parser.add_option('-D', dest='dstAddr', type='string', help='specify destination address. i.e 192.168.56.xx')
    parser.add_option('-A', dest='attack', type='string', help='simulate attack. i.e scan')

    (options, args) = parser.parse_args()
    srcAddr = options.srcAddr
    dstAddr = options.dstAddr
    attack  = options.attack

    if (srcAddr == None) | (dstAddr == None) | (attack ==None):
        print 'Invalid options'
        exit(0)

    if attack =='scan':
        scanSimulator(srcAddr , dstAddr)



if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print ""
        print "SALAM!"
        exit(0)
