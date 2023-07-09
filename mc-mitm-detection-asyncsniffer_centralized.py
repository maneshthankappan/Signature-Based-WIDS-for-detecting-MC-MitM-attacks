#!/usr/bin/env python3.9

# Signature-Based-WIDS-for-detecting-MC-MitM-attacks
# Copyright (c) 2023, Manesh Thankappan<mthankappan@uoc.edu>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

import time
from time import time, sleep
from threading import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Deauth, Dot11ProbeResp, Dot11, Dot11Elt, RadioTap, Dot11Disas
from scapy.layers.eap import EAPOL
from scapy.sendrecv import AsyncSniffer, sniff
import datetime
import statistics
import sys

logfile = open("logfile.txt", "a") # Logfile of SWIDS

# counter variables
cnt0: int = 0
cnt1: int = 0
cnt2: int = 0
cnt3: int = 0
cnt5_auth_seq_real: int = 0
cnt6_assoc_resp_real: int = 0
cnt7_eapol_real: int = 0
cnt5_auth_seq_rogue: int = 0
cnt6_assoc_resp_rogue: int = 0
cnt7_eapol_rogue: int = 0
cnt8_data_real: int = 0
cnt8_data_rogue: int = 0
bccc: int = 0  # beacon count on current channel
bcfc: int = 0  # beacon count on fake channel

pccc: int = 0  # probe response count on current channel
pcfc: int = 0  # probe response on fake channel
mf_rate: int = 0
r_flag = True
start = time()
start_datetime = datetime.datetime.now()
duration = 120

ssid = sys.argv[1]
ap_mac = sys.argv[2]
mac_list = sys.argv[3].split(";")
broad_mac = sys.argv[4]
instance_num = sys.argv[7]
thread_sleep_interval = int(sys.argv[8])

# status of stage 1 attack
const_jam_attack = 0
react_jam_attack = 0
csa_attack = 0
# status of stage 2 attack
con_beacon_probe = 0
con_connection_est = 0
con_data = 0
stage_1_attack_traffic = 0  # by default 0 represents false. Later in the program, if the value changes to 1,
# represents True
stage_2_attack_traffic = 0  # same as above
num = 10000  # No. of packets to be captured

today = datetime.datetime.now()
t = []  # List for managing FIAT
temp = 0
beacon = 0  # beacon counter for counting beacons during constant jamming attack

iface1 = sys.argv[5]
iface2 = sys.argv[6]


# Stage 1 traffic analysis
def constant_jamming():
    global constant_jamming_sniffer

    def constant_jamming_callback(frame):  # calculates frame inter-arrival time and counts total beacons received
        global temp, beacon, t
        if frame.haslayer(Dot11Beacon):
            bssid_addr = frame[Dot11].addr3
            if bssid_addr == ap_mac:
                # print(temp)
                iat = frame.time - temp
                t.append(iat)
                temp = frame.time
                beacon += 1

    constant_jamming_sniffer = AsyncSniffer(iface=iface1, count=num, prn=constant_jamming_callback, store=0,
                                            monitor=True)
    constant_jamming_sniffer.start()


constant_jamming_thread = Thread(target=constant_jamming)


def reactive_jamming():
    global reactive_jamming_sniffer

    def reactive_jamming_callback(frame):  # counts malformed beacons
        global cnt2
        if frame.haslayer(Dot11):
            b_addr = frame[Dot11].addr3
            if b_addr == ap_mac and (frame.haslayer(Dot11Beacon) or frame.haslayer(Dot11ProbeResp)):
                rl = frame.getlayer(RadioTap)
                if rl.Flags == "FCS+badFCS":  # Extract FCS flag
                    cnt2 += 1  # count malformed frames

    reactive_jamming_sniffer = AsyncSniffer(iface=iface1, count=num, prn=reactive_jamming_callback, store=0,
                                            monitor=True)
    reactive_jamming_sniffer.start()


reactive_jamming_thread = Thread(target=reactive_jamming)


def channel_switch():
    global channel_switch_sniffer

    def channel_switch_callback(frame):  # finds CSA beacons
        global cnt0
        if frame.haslayer(Dot11):
            b_addr = frame[Dot11].addr3
            if b_addr == ap_mac and (frame.haslayer(Dot11Beacon) or frame.haslayer(Dot11ProbeResp)):
                frame_elt = frame[Dot11Elt]
                while frame_elt:
                    if frame_elt.ID == 37:  # Extract Channel Switch Announcement Information Element
                        cnt0 += 1
                    frame_elt = frame_elt.payload

    channel_switch_sniffer = AsyncSniffer(iface=iface1, count=num, prn=channel_switch_callback, store=0, monitor=True)
    channel_switch_sniffer.start()


channel_switch_thread = Thread(target=channel_switch)


# Stage 2 traffic analysis
# Concurrent beacon traffic analysis
def concurrent_beacon_real():
    global concurrent_beacon_sniffer_real

    def concurrent_beacon_real_callback(frame):  # multiple beacon ananlysis for improved variant
        global bccc, bcfc
        if frame.haslayer(Dot11Beacon):
            getssid = str(frame.info)
            ap_ssid = getssid[2:len(getssid) - 1]
            bssid = frame[Dot11].addr3
            frequency = frame[RadioTap].Channel
            current_channel = (frequency - 2407) // 5
            # Extract Channel
            if (bssid == ap_mac or ssid == getssid) and current_channel == 1:
                bccc += 1

    concurrent_beacon_sniffer_real = AsyncSniffer(iface=iface1, count=num, prn=concurrent_beacon_real_callback, store=0,
                                                  monitor=True)  # wlan0 on ch 1, wlan1 on ch 11/13
    concurrent_beacon_sniffer_real.start()


concurrent_beacon_real_thread = Thread(target=concurrent_beacon_real)


def concurrent_beacon_rogue():
    global concurrent_beacon_sniffer_rogue

    def concurrent_beacon_rogue_callback(frame):  # multiple beacon analysis for improved variant
        global bccc, bcfc
        if frame.haslayer(Dot11Beacon):
            getssid = str(frame.info)
            ap_ssid = getssid[2:len(getssid) - 1]
            bssid = frame[Dot11].addr3
            frequency = frame[RadioTap].Channel
            current_channel = (frequency - 2407) // 5
            # Extract Channel
            if (bssid == ap_mac or ssid == getssid) and current_channel != 1:
                bcfc += 1

    concurrent_beacon_sniffer_rogue = AsyncSniffer(iface=iface2, count=num, prn=concurrent_beacon_rogue_callback,
                                                   store=0, monitor=True)  # wlan0 on ch 1, wlan1 on ch 11/13
    concurrent_beacon_sniffer_rogue.start()


concurrent_beacon_rogue_thread = Thread(target=concurrent_beacon_rogue)


def concurrent_probe_resp_real():
    global concurrent_probe_resp_sniffer_real

    def concurrent_probe_resp_real_callback(frame):  # multiple probe response ananlysis for improved variant
        global pccc, pcfc
        if frame.haslayer(Dot11ProbeResp):
            getssid = str(frame.info)
            ap_ssid = getssid[2:len(getssid) - 1]
            bssid = frame[Dot11].addr3
            frequency = frame[RadioTap].Channel
            current_channel = (frequency - 2407) // 5
            # Extract Channel
            if (bssid == ap_mac or ssid == getssid) and current_channel == 1:
                pccc += 1

    concurrent_probe_resp_sniffer_real = AsyncSniffer(iface=iface1, count=num, prn=concurrent_probe_resp_real_callback,
                                                      store=0, monitor=True)  # wlan0 on ch 1, wlan1 on ch 11/13
    concurrent_probe_resp_sniffer_real.start()


concurrent_probe_resp_real_thread = Thread(target=concurrent_probe_resp_real)


def concurrent_probe_resp_rogue():
    global concurrent_probe_resp_sniffer_rogue

    def concurrent_probe_resp_rogue_callback(frame):  # multiple probe response ananlysis for improved variant
        global pccc, pcfc
        if frame.haslayer(Dot11ProbeResp):
            getssid = str(frame.info)
            ap_ssid = getssid[2:len(getssid) - 1]
            bssid = frame[Dot11].addr3
            frequency = frame[RadioTap].Channel
            current_channel = (frequency - 2407) // 5
            # Extract Channel
            if (bssid == ap_mac or ssid == getssid) and current_channel != 1:
                pcfc += 1

    concurrent_probe_resp_sniffer_rogue = AsyncSniffer(iface=iface2, count=num,
                                                       prn=concurrent_probe_resp_rogue_callback, store=0,
                                                       monitor=True)  # wlan0 on ch 1, wlan1 on ch 11/13
    concurrent_probe_resp_sniffer_rogue.start()


concurrent_probe_resp_rogue_thread = Thread(target=concurrent_probe_resp_rogue)


# Concurrent auth traffic analysis

def concurrent_auth_real():
    global concurrent_auth_sniffer_real

    def concurrent_auth_real_callback(frame):
        global cnt5_auth_seq_real, cnt5_auth_seq_rogue
        if frame.haslayer(Dot11) and frame[Dot11].type == 0 and frame[Dot11].subtype == 11:
            bssid = frame[Dot11].addr3
            s_mac = frame[Dot11].addr2
            d_mac = frame[Dot11].addr1
            frequency = frame[RadioTap].Channel  # Extract Channel
            current_channel = (frequency - 2407) // 5
            if bssid == ap_mac and ((s_mac in mac_list) or (
                    d_mac in mac_list)) and current_channel == 1:
                cnt5_auth_seq_real += 1

    concurrent_auth_sniffer_real = AsyncSniffer(iface=iface1, count=num, prn=concurrent_auth_real_callback, store=0,
                                                monitor=True)  # wlan0 on ch 1, wlan1 on ch 11/13
    concurrent_auth_sniffer_real.start()


concurrent_auth_real_thread = Thread(target=concurrent_auth_real)


def concurrent_auth_rogue():
    global concurrent_auth_sniffer_rogue

    def concurrent_auth_rogue_callback(frame):
        global cnt5_auth_seq_real, cnt5_auth_seq_rogue
        if frame.haslayer(Dot11) and frame[Dot11].type == 0 and frame[Dot11].subtype == 11:
            bssid = frame[Dot11].addr3
            s_mac = frame[Dot11].addr2
            d_mac = frame[Dot11].addr1
            frequency = frame[RadioTap].Channel  # Extract Channel
            current_channel = (frequency - 2407) // 5
            if bssid == ap_mac and ((s_mac in mac_list) or (
                    d_mac in mac_list)) and current_channel != 1:
                cnt5_auth_seq_rogue += 1

    concurrent_auth_sniffer_rogue = AsyncSniffer(iface=iface2, count=num, prn=concurrent_auth_rogue_callback, store=0,
                                                 monitor=True)  # wlan0 on ch 1, wlan1 on ch 11/13
    concurrent_auth_sniffer_rogue.start()


concurrent_auth_rogue_thread = Thread(target=concurrent_auth_rogue)


def concurrent_association_real():
    # Concurrent association traffic analysis
    global concurrent_association_sniffer_real

    def concurrent_association_real_callback(frame):
        global cnt6_assoc_resp_real, cnt6_assoc_resp_rogue
        if frame.haslayer(Dot11) and frame[Dot11].type == 0 and frame[Dot11].subtype == 1:
            bssid = frame[Dot11].addr3
            s_mac = frame[Dot11].addr2
            d_mac = frame[Dot11].addr1
            frequency = frame[RadioTap].Channel  # Extract Channel
            current_channel = (frequency - 2407) // 5
            if bssid == ap_mac and ((s_mac in mac_list) or (
                    d_mac in mac_list)) and current_channel == 1:
                cnt6_assoc_resp_real += 1

    concurrent_association_sniffer_real = AsyncSniffer(iface=iface1, count=num,
                                                       prn=concurrent_association_real_callback, store=0,
                                                       monitor=True)  # wlan0 on ch 1, wlan1 on ch 11/13
    concurrent_association_sniffer_real.start()


concurrent_association_real_thread = Thread(target=concurrent_association_real)


def concurrent_association_rogue():
    global concurrent_association_sniffer_rogue

    def concurrent_association_rogue_callback(frame):
        global cnt6_assoc_resp_real, cnt6_assoc_resp_rogue
        if frame.haslayer(Dot11) and frame[Dot11].type == 0 and frame[Dot11].subtype == 1:
            bssid = frame[Dot11].addr3
            s_mac = frame[Dot11].addr2
            d_mac = frame[Dot11].addr1
            frequency = frame[RadioTap].Channel  # Extract Channel
            current_channel = (frequency - 2407) // 5
            if bssid == ap_mac and ((s_mac in mac_list) or (
                    d_mac in mac_list)) and current_channel != 1:
                cnt6_assoc_resp_rogue += 1

    concurrent_association_sniffer_rogue = AsyncSniffer(iface=iface2, count=num,
                                                        prn=concurrent_association_rogue_callback, store=0,
                                                        monitor=True)  # wlan0 on ch 1, wlan1 on ch 11/13
    concurrent_association_sniffer_rogue.start()


concurrent_association_rogue_thread = Thread(target=concurrent_association_rogue)


# Concurrent eapol traffic analysis

def concurrent_eapol_real():
    global concurrent_eapol_sniffer_real

    def concurrent_eapol_real_callback(frame):
        global cnt7_eapol_real, cnt7_eapol_rogue
        if frame.haslayer(EAPOL) and (frame[Dot11].type != 1):
            bssid = frame[Dot11].addr3
            s_mac = frame[Dot11].addr2
            d_mac = frame[Dot11].addr1
            frequency = frame[RadioTap].Channel  # Extract Channel
            current_channel = (frequency - 2407) // 5
            if bssid == ap_mac and ((s_mac in mac_list) or (
                    d_mac in mac_list)) and current_channel == 1:
                cnt7_eapol_real += 1

    concurrent_eapol_sniffer_real = AsyncSniffer(iface=iface1, count=num, prn=concurrent_eapol_real_callback, store=0,
                                                 monitor=True)  # wlan0 on ch 1, wlan1 on ch 11/13
    concurrent_eapol_sniffer_real.start()


concurrent_eapol_real_thread = Thread(target=concurrent_eapol_real)


def concurrent_eapol_rogue():
    global concurrent_eapol_sniffer_rogue

    def concurrent_eapol_rogue_callback(frame):
        global cnt7_eapol_real, cnt7_eapol_rogue
        if frame.haslayer(EAPOL) and (frame[Dot11].type != 1):
            bssid = frame[Dot11].addr3
            s_mac = frame[Dot11].addr2
            d_mac = frame[Dot11].addr1
            frequency = frame[RadioTap].Channel  # Extract Channel
            current_channel = (frequency - 2407) // 5
            if bssid == ap_mac and ((s_mac in mac_list) or (
                    d_mac in mac_list)) and current_channel != 1:
                cnt7_eapol_rogue += 1

    concurrent_eapol_sniffer_rogue = AsyncSniffer(iface=iface2, count=num, prn=concurrent_eapol_rogue_callback, store=0,
                                                  monitor=True)  # wlan0 on ch 1, wlan1 on ch 11/13
    concurrent_eapol_sniffer_rogue.start()


concurrent_eapol_rogue_thread = Thread(target=concurrent_eapol_rogue)


# Concurrent data traffic analysis
def concurrent_data_real():
    global concurrent_data_sniffer_real

    def concurrent_data_real_callback(frame):
        global cnt8_data_real, cnt8_data_rogue
        if frame.haslayer(Dot11) and frame[Dot11].subtype == 40:
            bssid = frame[Dot11].addr3
            s_mac = frame[Dot11].addr2
            d_mac = frame[Dot11].addr1
            frequency = frame[RadioTap].Channel  # Extract Channel
            current_channel = (frequency - 2407) // 5
            if bssid == ap_mac and ((s_mac in mac_list) or (
                    d_mac in mac_list)) and current_channel == 1:
                cnt8_data_real += 1

    concurrent_data_sniffer_real = AsyncSniffer(iface=iface1, count=num, prn=concurrent_data_real_callback, store=0,
                                                monitor=True)  # wlan2 on ch 11, wlan3 on ch 13 (rogue channels)
    concurrent_data_sniffer_real.start()


concurrent_data_real_thread = Thread(target=concurrent_data_real)


def concurrent_data_rogue():
    global concurrent_data_sniffer_rogue

    def concurrent_data_rogue_callback(frame):
        global cnt8_data_real, cnt8_data_rogue
        if frame.haslayer(Dot11) and frame[Dot11].subtype == 40:
            bssid = frame[Dot11].addr3
            s_mac = frame[Dot11].addr2
            d_mac = frame[Dot11].addr1
            frequency = frame[RadioTap].Channel  # Extract Channel
            current_channel = (frequency - 2407) // 5
            if bssid == ap_mac and ((s_mac in mac_list) or (d_mac in mac_list) and (current_channel != 1)):
                cnt8_data_rogue += 1

    concurrent_data_sniffer_rogue = AsyncSniffer(iface=iface2, count=num, prn=concurrent_data_rogue_callback, store=0,
                                                 monitor=True)  # wlan2 on ch 11, wlan3 on ch 13 (rogue channels)
    concurrent_data_sniffer_rogue.start()


concurrent_data_rogue_thread = Thread(target=concurrent_data_rogue)

# stage 1
constant_jamming_thread.start()
reactive_jamming_thread.start()
channel_switch_thread.start()
concurrent_beacon_real_thread.start()
concurrent_beacon_rogue_thread.start()
concurrent_probe_resp_real_thread.start()
concurrent_probe_resp_rogue_thread.start()
concurrent_auth_real_thread.start()
concurrent_auth_rogue_thread.start()
concurrent_association_real_thread.start()
concurrent_association_rogue_thread.start()
concurrent_eapol_real_thread.start()
concurrent_eapol_rogue_thread.start()
concurrent_data_real_thread.start()
concurrent_data_rogue_thread.start()

print("---------------------------------------------------------")
print(f"Probe interval number {instance_num} started at {start_datetime}")
logfile.write("\n---------------------------------------------------------")
logfile.write("\nProbe Interval " + str(instance_num))
logfile.write("    Started at  " + str(start_datetime))
print("---------------------------------------------------------")
# logfile.write("\n---------------------------------------------------------")
sleep(thread_sleep_interval)

constant_jamming_thread.join()
reactive_jamming_thread.join()
channel_switch_thread.join()
concurrent_beacon_real_thread.join()
concurrent_beacon_rogue_thread.join()
concurrent_probe_resp_real_thread.join()
concurrent_probe_resp_rogue_thread.join()
concurrent_auth_real_thread.join()
concurrent_auth_rogue_thread.join()
concurrent_association_real_thread.join()
concurrent_association_rogue_thread.join()
concurrent_eapol_real_thread.join()
concurrent_eapol_rogue_thread.join()
concurrent_data_real_thread.join()
concurrent_data_rogue_thread.join()

# set the status of stage 1 traffic
t.append(0.10)
t.append(0.10)
t.append(0.03)
t.pop(0)
# Calculating FIAT and FDR
var = statistics.pvariance(t)
fiat_std = statistics.pstdev(t)
fdr = (beacon / 600) * 100
mf_rate = (cnt2 / 60) * 100

if fiat_std > 2 or fdr > 50:
    const_jam_attack = 1
    stage_1_attack_traffic = 1
if mf_rate < 50:
    react_jam_attack = 1
    stage_1_attack_traffic = 1
if cnt0 > 1:
    csa_attack = 1
    stage_1_attack_traffic = 1

# set the status of stage 2 traffic

if (bccc > 0 and bcfc > 0) or (pccc > 0 and pcfc > 0):
    con_beacon_probe = 1

if (cnt5_auth_seq_real > 0 or cnt6_assoc_resp_real > 0 or cnt7_eapol_real > 0) or (
        cnt5_auth_seq_rogue > 0 or cnt6_assoc_resp_rogue > 0 or cnt7_eapol_rogue > 0):
    con_connection_est = 1

if cnt8_data_real > 0 and cnt8_data_rogue > 0:
    con_data = 1

if con_beacon_probe == 1 and (con_connection_est == 1 or con_data == 1):
    stage_2_attack_traffic = 1

print(f"-----------RESULTS OF PROBE INTERVAL {instance_num} started at {start_datetime}-------------------")
logfile.write("\n------------RESULTS OF----------------")
logfile.write("\nProbe Interval: " + str(instance_num))
logfile.write("   Time started: " + str(start_datetime))
# print("Const Jamming -FIAT =", fiat_std)
# print("Const Jamming -FDR =", fdr)
# print("Malformed_Beacon_Count =", cnt2)
# print("CSA_Count =", cnt0)
# print("-----------PREDICTED COUNTS OF STAGE 2 ATTACK TRAFFIC-------------------")
# print("Beacons on real channel : {0} \nBeacons on rogue channel : {1}".format(bccc, bcfc))
# print("Probe Response on real channel : {0} \nProbe Response on rogue channel : {1}".format(pccc, pcfc))
# print("Auth on real channel_Count =", cnt5_auth_seq_real)
# print("Auth on rogue channel_Count =", cnt5_auth_seq_rogue)
# print("Association  on real channel_Count =", cnt6_assoc_resp_real)
# print("Association  on rogue channel_Count =", cnt6_assoc_resp_rogue)
# print("EAPOL  on real channel_Count =", cnt7_eapol_real)
# print("EAPOL  on rogue channel_Count =", cnt7_eapol_rogue)
# print("Data  on real channel_Count =", cnt8_data_real)
# print("Data  on rogue channel_Count =", cnt8_data_rogue)
# print("------------PREDICTED STATUS OF ATTACK TRAFFIC--------------------------")
logfile.write("\n------------PREDICTED STATUS OF ATTACK TRAFFIC--------------------------")
print("Stage 1 attack traffic =", stage_1_attack_traffic)
logfile.write("\nStage 1 attack traffic: " + str(stage_1_attack_traffic))
print("Stage 2 attack traffic =", stage_2_attack_traffic)
logfile.write("\nStage 2 attack traffic:  " + str(stage_2_attack_traffic))
print("-------------------------------------------------------")
logfile.write("\n-----------------------------------------------------")

print("-Final Decision-")
logfile.write("\n-Final Decision-")
print("---------------------------------------------------------")
logfile.write("\n-------------------------------------------------")

if const_jam_attack == 1 and stage_2_attack_traffic == 1:
    print("\nConstant Jamming Attack Found")
    print("MC-MitM Base Variant Attack")
    logfile.write("\nConstant Jamming Attack Found")
    logfile.write("\nMC-MitM Base Variant Attack")
if react_jam_attack == 1 and stage_2_attack_traffic == 1:
    print("\nReactive Jamming Attack Found")
    print("MC-MitM Base Variant Attack")
    logfile.write("\nReactive Jamming Attack Found")
    logfile.write("\nMC-MitM Base Variant Attack")
if csa_attack == 1 and stage_2_attack_traffic == 1:
    print("\nFake CSA attack Found")
    print("MC-MitM Improved Variant Attack")
    logfile.write("\nFake CSA Attack Found")
    logfile.write("\nMC-MitM Base Variant Attack")
if stage_1_attack_traffic == 0 and stage_2_attack_traffic == 1:
    print("MC-MitM Attack Found")
    print("Attack Variant Unidentified")
    logfile.write("\nMC-MitM Attack Found")
    logfile.write("\nAttack Variant Unidentified")
if stage_1_attack_traffic == 1 and stage_2_attack_traffic == 0:
    print("Intentional Jamming Attack Found")
    logfile.write("\nIntentional Jamming Attack Found")
if stage_1_attack_traffic == 0 and stage_2_attack_traffic == 0:
    print("No MC-MitM Attack")
    logfile.write("\nNo MC-MitM Attack")
print("---------------------------------------------------------")
logfile.write("\n-------------------------------------------------")
end = time()
print("Elapsed time is  {} Minutes".format(round((end - start) / 60, 2)))
logfile.write("\nElapsed time =" + str((end - start) / 60) + " minutes")
logfile.write("\n--------------------END--------------------------")
logfile.close()
