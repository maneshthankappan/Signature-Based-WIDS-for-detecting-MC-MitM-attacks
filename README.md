# Signature-Based-WIDS-for-detecting-MC-MitM-attacks
This repository is a part of our research work entitled 
  <p align="center"> <img src="https://github.com/maneshthankappan/MC-MitM-Attack-Dataset/blob/main/Labels/title.png"></p>
and describes how to detect MC-MitM attack signatures in terms of pattern of network traffic. Kindly refer to our above research paper for more details of MC-MitM attacks and their variants.

## Prerequiste-Install Scapy
To install Scapy on Kali Linux, you can follow these steps:

Open a terminal in Kali Linux. You can do this by clicking on the terminal icon on the desktop or by using the shortcut Ctrl+Alt+T.

Update the package lists by running the following command:
```
sudo apt update
```
Once the package lists are updated, you can install Scapy by running the following command:
```
sudo apt install python3-scapy
```
During the installation, you may be prompted to confirm the installation by typing 'Y' and pressing Enter.
After the installation is complete, you should have Scapy installed on your Kali Linux system.
You can verify the installation by running the following command:

```
scapy
```
This should start the Scapy interactive shell if the installation was successful.

## Prerequiste-Attach Wi-Fi adapters
Attach any two commercially available Wi-Fi adapters. We use TP-Link WN722N v3 (High Gain) Wi-Fi adapters for 2.4 Ghz and Wi-Fi Nation for 5GHz channels.

## Prerequiste-Install RF-kill

*Before doing any attacks it is recommended to disable WiFi.* In particular I mean disabling WiFi in your network manager. Most graphical network managers have an option somewhere named "Enable Wi-Fi". Make sure it's not selected. If you can't find it, perhaps you can disable in the terminal with `sudo nmcli nm wifi off`. Once you have disabled WiFi your OS won't interfere with our attacks.

*If RF-kill is enabled* we'll have to turn it off. Some distributions set RF-kill on after disabling WiFi. But we still want to actually use our WiFi devices. So execute:

```bash
sudo apt-get install rfkill
sudo rfkill unblock wifi
```
## Quick Start

From this repository, download all the 3 files (SWIDS.py,mc-mitm-detection-asyncsniffer_centralized.py, and macaddresses.json) and keep all of them in a same folder. Alternatively you can download SWIDS.tar.gz. 

## How to run the SWIDS

In the terminal, write  
```bash
sudo python3 SWIDS.py
```
### Description
