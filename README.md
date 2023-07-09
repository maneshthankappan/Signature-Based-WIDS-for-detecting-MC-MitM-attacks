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
```bash
SWIDS is active.........
0. wlan1
1. eth0
2. lo
3. wlan0
4. wlan2
Select iface1: 0
0. wlan1
1. eth0
2. lo
3. wlan0
4. wlan2
Select iface2: 4
Select your adapter operation frequency
0. 2.4 Ghz
1. 5 Ghz
Enter number 0 or 1: 0
------------------------------------------

ESSID: Padmayil
BSSID: 14:A7:2B:2F:DA:CA
Channel: 1
------------------------------------------
Clients Connected
------------------------------------------
1. 4C:53:FD:49:34:E3 - Amazon Technologies Inc.
2. 24:18:1D:2D:58:DB - SAMSUNG ELECTRO-MECHANICS(THAILAND)
3. 92:F3:0F:D5:40:1B - Unknown vendor
4. D0:37:45:81:9A:68 - TP-LINK TECHNOLOGIES CO.,LTD.
5. 74:23:44:AA:DC:B9 - Xiaomi Communications Co Ltd
6. 42:EB:6B:65:43:EA - Unknown vendor
7. 8C:29:37:AD:7B:49 - Apple, Inc.
8. 8C:F5:A3:08:16:63 - SAMSUNG ELECTRO-MECHANICS(THAILAND)
------------------------------------------
Starting MC-MitM Detection
---------------------------------------------------------
Probe interval number 1 started at 2023-07-08 19:50:06.360754
---------------------------------------------------------                                                                                                     ---------------------------------------------------------
Probe interval number 2 started at 2023-07-08 19:50:26.141916
---------------------------------------------------------
---------------------------------------------------------
Probe interval number 3 started at 2023-07-08 19:50:46.531040
---------------------------------------------------------
-----------RESULTS OF PROBE INTERVAL 1 started at 2023-07-08 19:50:06.360754-------------------
Stage 1 attack traffic = 0
Stage 2 attack traffic = 0
-------------------------------------------------------
-Final Decision-
---------------------------------------------------------
No MC-MitM Attack Found
---------------------------------------------------------
Elapsed time is  1.0 Minutes
---------------------------------------------------------
Probe interval number 4 started at 2023-07-08 19:51:07.089282
---------------------------------------------------------
-----------RESULTS OF PROBE INTERVAL 2 started at 2023-07-08 19:50:26.141916-------------------
Stage 1 attack traffic = 1
Stage 2 attack traffic = 1
-------------------------------------------------------
-Final Decision-
---------------------------------------------------------
Reactive Jamming Attack Found
MC-MitM Base Variant Attack
---------------------------------------------------------
Elapsed time is  1.0 Minutes
---------------------------------------------------------
Probe interval number 5 started at 2023-07-08 19:51:27.051527
---------------------------------------------------------
-----------RESULTS OF PROBE INTERVAL 3 started at 2023-07-08 19:50:46.531040-------------------
Reactive Jamming Attack Found
MC-MitM Base Variant Attack
-------------------------------------------------------
-Final Decision-
---------------------------------------------------------
Intentional Jamming Attack Found
---------------------------------------------------------
Elapsed time is  1.01 Minutes
---------------------------------------------------------
Probe interval number 6 started at 2023-07-08 19:51:47.279836
---------------------------------------------------------
-----------RESULTS OF PROBE INTERVAL 4 started at 2023-07-08 19:51:07.089282-------------------
Stage 1 attack traffic = 1
Stage 2 attack traffic = 0
-------------------------------------------------------
-Final Decision-
---------------------------------------------------------
Intentional Jamming Attack Found
---------------------------------------------------------
Elapsed time is  1.0 Minutes
---------------------------------------------------------
Probe interval number 7 started at 2023-07-08 19:52:11.353508
---------------------------------------------------------
-----------RESULTS OF PROBE INTERVAL 5 started at 2023-07-08 19:51:27.051527-------------------
Stage 1 attack traffic = 1
Stage 2 attack traffic = 0
-------------------------------------------------------
-Final Decision-
---------------------------------------------------------
Intentional Jamming Attack Found
---------------------------------------------------------
Elapsed time is  1.01 Minutes
---------------------------------------------------------
Probe interval number 8 started at 2023-07-08 19:52:31.373013
---------------------------------------------------------
-----------RESULTS OF PROBE INTERVAL 6 started at 2023-07-08 19:51:47.279836-------------------
Stage 1 attack traffic = 1
Stage 2 attack traffic = 1
-------------------------------------------------------
-Final Decision-
---------------------------------------------------------
Fake CSA attack Found
MC-MitM Improved Variant Attack
---------------------------------------------------------
Elapsed time is  1.01 Minutes
---------------------------------------------------------
Probe interval number 9 started at 2023-07-08 19:52:48.977689
```
