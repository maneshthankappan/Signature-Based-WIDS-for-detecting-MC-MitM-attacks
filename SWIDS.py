# Signature-Based-WIDS-for-detecting-MC-MitM-attacks
# Copyright (c) 2023, Manesh Thankappan<mthankappan@uoc.edu>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

from impacket.dot11 import Dot11
from scapy.all import *
from time import sleep
from sys import argv
from subprocess import run
import threading
import json
import os
import re

from scapy.layers.dot11 import Dot11Beacon, Dot11Elt

if os.getuid() != 0:  # check if the script running as root
    print("Run as root")
    exit()

iface1 = "wlan1"
iface2 = "wlan2"
bssid = ""
essid = ""
freq = ""
channel = ""
mac_dict = {}  # dictonary which stores all mac addresses and their vendor names
mac_list = []
running = True  # variable used to close the printing while loop when cntrl+c pressed
dict_writable = True
python_command = "python3"
ids_script = "mc-mitm-detection-asyncsniffer_centralized.py"
broad_mac = "ff:ff:ff:ff:ff:ff"
start_delay = 300  # delay in seconds after which to start the IDS script.
launch_interval = 20  # launch interval in seconds after which a new instance of the IDS script starts
probe_interval = 60  # how long
instances_launched = 0


def get_bssid(essid):
    def callback(frame):
        # allow function to access global variables
        global bssid
        global channel
        if frame.haslayer(Dot11Beacon) and frame[
            Dot11Elt].info.decode() == essid:  # check if a packet has a 802.11 beacon frame with the essid entered in the input
            bssid = frame[Dot11].addr2  # set the bssid variable to the frame's senders address
            channel = frame[Dot11].channel  # set the channel variable to the channel the frame was sent on

    while bssid == "":  # while bssid isn't changed from initial value sniff 10 more packets and check them with the callback function
        # channel_hopper_bssid() is running on another thread while this function is running
        sniff(iface=iface1, count=10, prn=callback)


def get_essid(bssid):
    def callback(frame):
        # allow function to access global variables
        global essid
        global channel
        if frame.haslayer(Dot11Beacon) and frame[
            Dot11].addr2 == bssid:  # check if a packet has a 802.11 beacon frame and the bssid entered in the input matches the beacon's senders address
            essid = frame[Dot11Elt].info.decode()  # set the essid variable to the value contained in the beacon
            channel = frame[Dot11].channel  # set the channel variable to the channel the frame was sent on

    while essid == "":  # while essid isn't changed from initial value sniff 10 more packets and check them with the callback function
        sniff(iface=iface1, count=10, prn=callback)


def get_vendor(mac_address):
    file = open("macaddresses.json", "r")  # open the mac address json file
    dict = json.load(file)  # parse the json into a dictonary
    file.close()  # close the file
    for i in dict:  # search the dictonary for the brand name of the specified mac address prefix
        macprefix_len = len(i["macPrefix"])
        if i["macPrefix"] in mac_address[
                             :macprefix_len]:  # if the first part of the mac address matches the current for loop item
            return i["vendorName"]  # return the vendor name of current foor loop item
    return "Unknown vendor"  # if no name associated with the Mac address was found in the dictionary, returns an unknown vendor


def scanner_func():  # function which scans for client mac addreses
    # allow access to global variables
    global sniffer
    global bssid
    global dict_writable

    def callbackfunc(frame):
        if frame.haslayer(Dot11):
            if frame[Dot11].type == 2 and frame[
                Dot11].addr1 == bssid:  # if a type 2(Data) frame and frame's sender address is the aps bssid
                if "33:33" not in frame[Dot11].addr2 and "01:00:5e" not in frame[Dot11].addr2 and frame[
                    Dot11].addr2.upper() not in mac_dict:
                    # if the frame's destination address(Client's mac address) not in mac address dictonary and if the frame's senders address isn't in any of multicast groups
                    while not dict_writable:  # if dictonary isn't currently wirtable wait 50 ms
                        time.sleep(0.05)
                    mac_dict[frame[Dot11].addr2.upper()] = get_vendor(
                        frame[Dot11].addr2.upper())  # add the clients mac address to the dictonary
                    mac_list.append(frame[Dot11].addr2.upper())
            elif "33:33" not in frame[Dot11].addr1 and "01:00:5e" not in frame[Dot11].addr1 and frame[
                Dot11].type == 2 and frame[Dot11].addr2 == bssid:
                if frame[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" and frame[Dot11].addr1.upper() not in mac_dict:
                    while not dict_writable:
                        time.sleep(0.05)
                    mac_dict[frame[Dot11].addr1.upper()] = get_vendor(frame[Dot11].addr1.upper())
                    mac_list.append(frame[Dot11].addr1.upper())
        sleep(0.01)

    sniffer = AsyncSniffer(iface=iface1, prn=callbackfunc)
    sniffer.start()


def mainloop():  # function with displays mac addreses on the terminal
    global running
    global dict_writable

    def print_w_spaces(string, max_len, end_with_newline):
        spaces = max_len - len(string)
        print(string, end="")
        for i in range(spaces):
            print(" ", end="")
        if end_with_newline:
            print("")

    while running:
        subprocess.run("clear")  # clear the previously cleared output
        print("------------------------------------------")
        print(f"ESSID: {essid}")
        print(f"BSSID: {bssid.upper()}")
        print(f"Channel: {channel}")
        print("------------------------------------------")
        print("Clients Connected")
        print("------------------------------------------")
        dict_writable = False  # set the dict_writable variable to false to prevent "dictonary changed size durring itteration error"
        for i in mac_dict:  # print all mac addresess stored in mac address dictonary
            print_w_spaces(str(list(mac_dict.keys()).index(i) + 1) + ".", 3, False)
            print(i.upper(), end=" - ")
            print(mac_dict[i])
        dict_writable = True  # set the ditct_writable to true
        print("------------------------------------------")
        sleep(0.2)


def channel_hopper_essid():
    # function changes the channel on the interface to find on which channel is the essid
    global freq
    global channel
    global essid
    if freq == "2.4":
        for i in range(15)[1::]:
            subprocess.run(["iwconfig", iface1, "channel", str(i)])
            sleep(0.35)
            if essid != "":  # if essid is different from the initial value and changed by the get_essid() function the for loop brakes and the channel hopper stops
                break
    elif freq == "5":
        for i in ["36", "40", "44", "48", "52", "56", "60", "64", "68", "72", "76", "80", "84", "88", "92",
                  "96", "100", "104", "108", "112", "116", "120", "124", "128", "132", "136", "140", "144", "149",
                  "153",
                  "157", "161", "165", "169", "173", "177", "181"]:
            subprocess.run(["iwconfig", iface1, "channel", i])
            sleep(0.35)
            if essid != "":  # if essid is different from the initial value and changed by the get_essid() function the for loop brakes and the channel hopper stops
                break


def channel_hopper_bssid():
    # function changes the channel on the interface to find on which channel is the bssid
    global freq
    global channel
    global bssid
    if freq == "2.4":
        for i in range(15)[1::]:
            subprocess.run(["iwconfig", iface1, "channel", str(i)])
            sleep(0.35)
            if bssid != "":  # if bssid is different from the initial value and changed by the get_bssid() function the for loop brakes and the channel hopper stops
                break
    elif freq == "5":
        for i in ["36", "40", "44", "48", "52", "56", "60", "64", "68", "72", "76", "80", "84", "88", "92",
                  "96", "100", "104", "108", "112", "116", "120", "124", "128", "132", "136", "140", "144", "149",
                  "153",
                  "157", "161", "165", "169", "173", "177", "181"]:
            subprocess.run(["iwconfig", iface1, "channel", i])
            sleep(0.35)
            if bssid != "":  # if bssid is different from the initial value and changed by the get_bssid() function the for loop brakes and the channel hopper stops
                break


scanner_thread = threading.Thread(target=scanner_func)
display_thread = threading.Thread(target=mainloop)
# define a thread for scanner_func() and mainloop()

# iface1
print("SWIDS is active.........")
ifaces = os.listdir('/sys/class/net/')  # get a list of all network interfaces on the machine
print("Select iface1: ")
for i in ifaces:
    print(f"{ifaces.index(i)}. {i}")
# print out all network interfaces and their indexes in the list

prompt = f"Enter number(0-{len(ifaces) - 1}): "
while iface1 == "":
    try:
        inp = input(prompt)  # get the input from user
        ifaces[int(inp)]  # check if the list has an item with the entered index
    except KeyboardInterrupt:  # in case if cntrl+c pressed while entering the input
        print("\nExiting...")
        exit()
    except:  # in case code at the try statement did not succeed
        prompt = f"\nPlease choose from the list(0-{len(ifaces) - 1}): "
    else:  # executed only if the code at try statement succeeded
        iface1 = ifaces[int(inp)]
        subprocess.run(["ifconfig", iface1, "down"])
        subprocess.run(["iwconfig", iface1, "mode", "monitor"])
        subprocess.run(["ifconfig", iface1, "up"])

# iface2

ifaces = os.listdir('/sys/class/net/')  # get a list of all network interfaces on the machine
print("Select iface2: ")
for i in ifaces:
    print(f"{ifaces.index(i)}. {i}")
# print out all network interfaces and their indexes in the list

prompt = f"Enter number(0-{len(ifaces) - 1}): "
while iface2 == "":
    try:
        inp = input(prompt)  # get the input from user
        ifaces[int(inp)]  # check if the list has an item with the entered index
    except KeyboardInterrupt:  # in case if cntrl+c pressed while entering the input
        print("\nExiting...")
        exit()
    except:  # in case code at the try statement did not succeed
        prompt = f"\nPlease choose from the list(0-{len(ifaces) - 1}): "
    else:  # executed only if the code at try statement succeeded
        iface2 = ifaces[int(inp)]
        subprocess.run(["ifconfig", iface2, "down"])
        subprocess.run(["iwconfig", iface2, "mode", "monitor"])
        subprocess.run(["ifconfig", iface2, "up"])

print("Select your adapter operation frequency")
print("0. 2.4 Ghz")
print("1. 5 Ghz")
while freq == "":
    try:
        inp = input("Enter number 0 or 1: ")
    except KeyboardInterrupt:  # in case cntrl+c pressed while on the input
        print("\nExiting...")
        exit()
    else:  # when input submitted
        if inp == "0":  # if input is 1 set the freq variable to 2.4
            freq = "2.4"
        elif inp == "1":  # if input is 1 set the freq variable to 5
            freq = "5"
        else:  # in case input isn't 0 or 1
            continue

print('Mac address formats supported: "AA:BB:CC:DD:EE:FF", "AA-BB-CC-DD-EE-FF"')
print("Letters can be both lowerace and uppercase for mac addreses")
try:
    inp = input("Enter BSSID or SSID of the AP: ")
except KeyboardInterrupt:  # in case cntrl+c pressed while on the input
    print("\nExiting...")
    exit()
if re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9a-fA-F]{4}\\.[0-9a-fA-F]{4}\\.[0-9a-fA-F]{4})$",
             inp.strip()):
    # if the input matches the regex pattern it is set as the bssid
    if "-" in inp:  # if the mac address entered in format with "-" replace them with ":" so scapy can understand it
        inp = inp.replace("-", ":")
    print(f"Searching for ESSID associated with {inp}...")
    bssid = inp.strip().lower()  # remove all leading and trailing whitespaces from the input and convert all letters to lowercase so scapy can understand it and assign it to bssid variable
    hopper_thread = threading.Thread(target=channel_hopper_essid)
    hopper_thread.start()  # asynchronously start the thread with the function channel_hopper_essid()
    get_essid(bssid)
else:
    # if the input doesn't match the regex pattern it is set as essid
    print(f"Searching for BSSID associated with {inp}...")
    essid = inp
    hopper_thread = threading.Thread(target=channel_hopper_bssid)
    hopper_thread.start()
    get_bssid(essid)

scanner_thread.start()
display_thread.start()
# start both threads
print("sleeping fro stgart dellay\n\n\n\n\n\n\n\n")
sleep(start_delay)
print("Starting MC-MitM detection...")
if len(mac_list) == 0:
    print("Couldn't find any clients")
    print("Exiting...")
    exit()
running = False  # Set the printing while loop variable to false
sniffer.stop()  # Stop the async sniffer
scanner_thread.join()
display_thread.join()

while True:
    instances_launched += 1
    t = threading.Thread(target=run, args=(
    [python_command, ids_script, essid, bssid, ";".join(mac_list), broad_mac, iface1, iface2, str(instances_launched),
     str(probe_interval)],))
    t.start()
    sleep(launch_interval)
