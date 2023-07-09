# Signature-Based-WIDS-for-detecting-MC-MitM-attacks
This repository is a part of our research work entitled 
  <p align="center"> <img src="https://github.com/maneshthankappan/MC-MitM-Attack-Dataset/blob/main/Labels/title.png"></p>
and describes how to detect MC-MitM attack signatures in terms of pattern of network traffic. Kindly refer to our above research paper for more details of MC-MitM attacks and their variants.

## Prerequisite-Install Scapy
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

## Prerequisite-Attach Wi-Fi adapters
Attach any two commercially available Wi-Fi adapters. We use TP-Link WN722N v3 (High Gain) Wi-Fi adapters for 2.4 Ghz and Wi-Fi Nation for 5GHz channels.

## Prerequisite-Install RF-kill

*Before doing any attacks it is recommended to disable WiFi.* In particular I mean disabling WiFi in your network manager. Most graphical network managers have an option somewhere named "Enable Wi-Fi". Make sure it's not selected. If you can't find it, perhaps you can disable in the terminal with `sudo nmcli nm wifi off`. Once you have disabled WiFi your OS won't interfere with our attacks.

*If RF-kill is enabled* we'll have to turn it off. Some distributions set RF-kill on after disabling WiFi. But we still want to actually use our WiFi devices. So execute:

```bash
sudo apt-get install rfkill
sudo rfkill unblock wifi
```
## Quick Start

From this repository, download all the 3 files (SWIDS.py,mc-mitm-detection-asyncsniffer_centralized.py, and macaddresses.json) and keep all of them in a same folder. Alternatively you can download SWIDS.tar.gz. 
### Description of Python Scripts
##### SWIDS.py: 
The following script prompts the user to select a Wi-Fi card, specify the Wi-Fi frequency (2.4GHz/5GHz), and provide the SSID of the target access point (AP) in the Wi-Fi network. It then automatically identifies all clients connected to the AP and forwards their MAC addresses along with the AP's MAC address to the "mc-mitm-detection-asyncsniffer_centralized.py" script.

Make sure you have the "mc-mitm-detection-asyncsniffer_centralized.py" script in the same directory, or provide the full path to the script if it's located elsewhere. This script will pass the selected Wi-Fi card, Wi-Fi frequency, and SSID as command-line arguments to the "mc-mitm-detection-asyncsniffer_centralized.py" script, which will handle the further processing.
##### macaddresses.json:
This file is utilized by the "SWIDS.py" script to retrieve the vendor details of connected clients by using their MAC addresses.
##### mc-mitm-detection-asyncsniffer_centralized.py: 
This script combines various detection logic discussed in Section 5 of our paper with the algorithms presented in Appendix 1. Its main purpose is to identify the presence of MC-MitM attacks by verifying the status of stage 1 and stage 2 attacks based on attack signatures. For more detailed information, please refer to Section 3 of our paper.

The script is designed to be executed with a probe interval of 60 seconds. After the first probe interval, the same script will be executed in another thread with a delay of 10 seconds. This approach ensures continuous monitoring, allowing the SWIDS to make attack decisions every 10 seconds after the initial probe interval.

## How to run the SWIDS

In the terminal, write  
```bash
sudo python3 SWIDS.py
```
### Sample output

