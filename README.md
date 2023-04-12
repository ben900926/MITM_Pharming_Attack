# MITM_Pharming_Attack

### How to Run
Start two VMs that shares a same subnet (using same Nat network)

- Attacker VM
```
make clean && make
sudo ./mitm_attack
sudo ./pharm_attack
```

#### MITM attack
After victim enter its username and password,
these information will be printed on terminal

- Victim VM

Open NYCU e3 login.php
then enter username and password

#### Pharm attack
Using 無痕模式 firefox, connect to the following link in victim VM:

```
www.nycu.edu.tw
```

You should see the fake website instead of real google address
