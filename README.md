# MITM_Pharming_Attack

### How to Run
Start two VMs that shares a same subnet (using same Nat network)

- Attacker VM
> If you need to install python module (scapy and wheel), you should use `make install` beforehand
```
make clean && make
sudo ./mitm_attack
```
After victim enter its username and password,
these information will be printed on terminal

- Victim VM

Open NYCU e3 login.php
then enter username and password
