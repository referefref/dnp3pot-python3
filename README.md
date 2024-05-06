![image](https://github.com/referefref/dnp3pot-python3/assets/56499429/554cb2e0-26b3-4072-8f8a-39e592039f55)


## Dnp3-Python3 Honeypot installation instructions
- [***Originally created by David Olano (ArtWachowski)***](https://github.com/ArtWachowski/dnp3pot) and ported to Python3 by James Brine.
- IP and PORT are for your rsyslog server, original author had this connected to Splunk instance. Bogus settings can be provided here or rsyslog settings commented out from installation script if preferred.

### MacOS
```
# Assuming brew is installed
brew install python3 python3-pip git
git clone https://github.com/referefref/dnp3pot-python3.git
cd dnp3pot-python3
pip3 install -r requirements.txt
# Update installme.sh to your requirements
./installme.sh <IP> <PORT>
sudo python3 DNP3pot.py # sudo is needed by python3 sockets to get current ip
```

### Debian/Ubuntu/Kali
```
apt-get install python3 python3-pip git
git clone https://github.com/referefref/dnp3pot-python3.git
cd dnp3pot-python3
pip3 install -r requirements.txt
# Update installme.sh to your requirements
./installme.sh <IP> <PORT>
sudo python3 DNP3pot.py # sudo is needed by python3 sockets to get current ip
```

## DNP3Crafter
``` This tool allows for execution of simple dnp3 checks and attacks for testing the honeypot - updated to python3 ```

![image](https://github.com/referefref/dnp3pot-python3/assets/56499429/7db23115-482d-4eab-a153-2e6e902d01b7)


## Logs
Logs can be read localy with a command "tail -f /var/log/dnp3pot.log &"
```
2024-05-06 15:06:16,258 - __main__ - INFO - New connection from ('192.168.1.193', 51231)

2024-05-06 15:06:16,267 - __main__ - INFO - Raw data received from ('192.168.1.193', 51231) rawdata: b'' encoding: None

2024-05-06 15:10:50,075 - __main__ - INFO - New connection from ('192.168.1.193', 52882)

2024-05-06 15:10:50,080 - __main__ - INFO - Raw data received from ('192.168.1.193', 52882) rawdata: b'\x05d\x05\xc3\x80\x01\x00\x00\x04\xc3\xa9!' encoding: utf-8
```
