# Packet sniffer
A packet sniffer made using python which monitors local network traffic and displays the data obtained from disassembling the packets arriving at the network.

This repo contains implementations in both command line and graphical user interfaces. 


# Prerequisites
This project needs the following dependencies to be installed:
* PyQt5 - 
`pip install PyQt5`
* pcapy - `pip install pcapy`

# Installation
To get this repo up and running in your local machine, follow the following steps:

Firstly, clone this repository using the below command:

```
git clone https://github.com/legbing/packet-sniffer.git`
cd packet-sniffer
```

 #### To run the command line program:
`sudo python3 packet_sniffer.py`

#### To run the GUI program:
`sudo python3 packet_sniffer_gui.py`

Make sure that it is run with sudo as the program needs root privileges.

**Note: This script has not been tested on Windows and might need additional packages for pcapy to work.**
