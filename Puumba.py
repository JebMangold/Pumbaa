#!/usr/bin/python3
import subprocess
import sys
import argparse
import re
import glob
import os


def network_capture():
    print("Please specify what interface you would like to capture on")
    interface=input()
    print("Please specify how long you would like to run this scan in seconds")
    time=input()
    duration=(f'duration:{time}')
    cmd =['tshark', '-i',interface,'-a',duration,'-w','traffic.pcapng']#our command

    d = open('traffic.pcapng', 'w') #this creates the file

    subprocess.run(cmd)#this sends it to f
    print('Saved Captured Network Traffic to file name traffic.pcapng')

host_IP = subprocess.check_output(['hostname', '--all-ip-addresses'])
host_IP=host_IP.split()
host_IP2=[]
for ip in host_IP:
    ip = ip.decode()
    host_IP2.append(ip)


def dos(pcap):
    seconds = 'xx'
    event_count = 0
    event_list = []
    IP_list=[]
    src_ip=[]
    timestamps=[]
    tshark_traffic=subprocess.check_output(['tshark','-r',pcap,'-Y http.request.method == "GET"']).decode("utf-8")
    tshark_traffic = tshark_traffic.split('\n')
    for line in tshark_traffic:
        strings = line.split()
        if len(strings) != 0:
            timestamps.append(strings[2])
            IP_list +=re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} →',line)
            for i in IP_list:
                i=i.replace(' →','')
                src_ip.append(i)
    for i in range(len(timestamps)):
        if timestamps[i][6:8] != seconds:
            event_list.append(event_count)
            seconds = timestamps[i][6:8]
            event_count = 1
            if len(event_list) == 10:
                event_list.pop(0)
        else:
            event_count += 1
        if i == len(timestamps)-1:
            event_list.append(event_count)
    src_ip=set(src_ip)
    if sum(event_list) >= 35:
        for i in host_IP2:
            for ip in src_ip:
                snort = open('SNORT_Rules.txt','a+')
                n = snort.write(f'Alert any {ip} any -> {i} (sid:1000003; MSG:"POSSIBLE HTTP FLOOD DoS")\n')
                ufw = open('UFW_Rules.txt','a+')
                u = ufw.write(f'sudo ufw deny from {ip}\n')
                snort.close()
                ufw.close()

                



def ping(pcap):
    IP_list =[]
    tshark_traffic=subprocess.check_output(['tshark','-r',pcap]).decode("utf-8")
    tshark_traffic = tshark_traffic.split('\n')
    for line in tshark_traffic:#looks through every line in opened file
        strings = line.split()#splits the line into individual strings
        if 'ICMP' in strings:#checks if ICMP appears in strings
            IP_list +=re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',line)#grabs IP from each ICMP scan
            IP_set = set(IP_list)#gives only unique IP
    snort = open('SNORT_Rules.txt','a+')#opens new file, saves reccomended snort rule
    if IP_list:
        for i in IP_set:
            if i not in host_IP2:
                for ip in host_IP2:
                    n = snort.write(f'Alert ICMP {i} any -> {ip} (sid:1000002; MSG:"PING attempt")\n')#makes the snort rule
        snort.close()
        ufw = open('UFW_Rules.txt','a+')#opens new file, saves reccomended UFW rules
        for i in IP_set:
            if i not in host_IP2:
                for ip in host_IP2:
                    u = ufw.write(f'sudo ufw deny from {i}\n')
        ufw.close()


def SYN_DOS(pcap):
    seconds = 'xx'
    event_count = 0
    event_list = []
    IP_list=[]
    src_ip=[]
    timestamps=[]
    tshark_traffic=subprocess.check_output(['tshark','-r',pcap,'-Y','tcp.flags.syn==1 and tcp.flags.ack==0']).decode("utf-8")
    tshark_traffic = tshark_traffic.split('\n')
    for line in tshark_traffic:
        strings = line.split()
        if len(strings) != 0:
            if '[SYN]' in strings:
                timestamps.append(strings[2])
                IP_list +=re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} →',line)
            for i in IP_list:
                i=i.replace(' →','')
                src_ip.append(i)
    src_ip=sorted(src_ip)
    compare = {}
    for i in range(len(timestamps)):
        if timestamps[i][6:8] != seconds:
            event_list.append(event_count)
            seconds = timestamps[i][6:8]
            event_count = 1
            if len(event_list) == 10:
                event_list.pop(0)
        else:
            event_count += 1
        if i == len(timestamps)-1:
            event_list.append(event_count)
    src_ip= set(src_ip)
    if sum(event_list) >= 1100:
        for i in host_IP2:
            for ip in src_ip:
                snort = open('SNORT_Rules.txt','a+')
                n = snort.write(f'Alert any {ip} any -> {i} (sid:1000003; MSG:"POSSIBLE SYN DOS ATTACK")\n')
                ufw = open('UFW_Rules.txt','a+')
                u = ufw.write(f'sudo ufw deny from {ip}\n')
                snort.close()
                ufw.close()

def xmas(pcap):
    seconds = 'xx'
    event_count = 0
    event_list = []
    IP_list=[]
    src_ip=[]
    timestamps=[]
    tshark_traffic=subprocess.check_output(['tshark','-r',pcap,'-Y','tcp.flags.fin==1 and tcp.flags.urg==1 and tcp.flags.push==1']).decode("utf-8")
    tshark_traffic = tshark_traffic.split('\n')
    for line in tshark_traffic:
        strings = line.split()
        if len(strings) != 0:
            timestamps.append(strings[2])
            IP_list +=re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} →',line)
            for i in IP_list:
                i=i.replace(' →','')
                src_ip.append(i)
    for i in range(len(timestamps)):
        if timestamps[i][6:8] != seconds:
            event_list.append(event_count)
            seconds = timestamps[i][6:8]
            event_count = 1
            if len(event_list) == 10:
                event_list.pop(0)
        else:
            event_count += 1
        if i == len(timestamps)-1:
            event_list.append(event_count)
    src_ip = set(src_ip)
    if sum(event_list) >= 500:
        for i in host_IP2:
            for ip in src_ip:
                snort = open('SNORT_Rules.txt','a+')
                n = snort.write(f'Alert any {ip} any -> {i} (sid:1000003; MSG:"POSSIBLE NMAP XMAS SCAN")\n')
                ufw = open('UFW_Rules.txt','a+')
                u = ufw.write(f'sudo ufw deny from {ip}\n')
                snort.close()
                ufw.close()

def stealth_scans(pcap):
    seconds = 'xx'
    event_count = 0
    event_list = []
    IP_list=[]
    src_ip=[]
    timestamps=[]
    tshark_traffic=subprocess.check_output(['tshark','-r',pcap,'-Y','tcp.flags.reset==1 and tcp.flags.ack==1']).decode("utf-8")
    tshark_traffic = tshark_traffic.split('\n')
    for line in tshark_traffic:
        strings = line.split()
        if len(strings) != 0:
            timestamps.append(strings[2])
            IP_list +=re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} →',line)
            for i in IP_list:
                i=i.replace(' →','')
                src_ip.append(i)
    for i in range(len(timestamps)):
        if timestamps[i][6:8] != seconds:
            event_list.append(event_count)
            seconds = timestamps[i][6:8]
            event_count = 1
            if len(event_list) == 10:
                event_list.pop(0)
        else:
            event_count += 1
        if i == len(timestamps)-1:
            event_list.append(event_count)
    src_ip=set(src_ip)
    if sum(event_list) >= 1000:
        for i in host_IP2:
            for ip in src_ip:
                snort = open('SNORT_Rules.txt','a+')
                n = snort.write(f'Alert any {ip} any -> {i} (sid:1000003; MSG:"POSSIBLE NMAP Stealth SCAN")\n')
                ufw = open('UFW_Rules.txt','a+')
                u = ufw.write(f'sudo ufw deny from {ip}\n')
                snort.close()
                ufw.close()

def open_pcap():
    pcap=sys.argv[2]
    dos(pcap)
    ping(pcap)
    SYN_DOS(pcap)
    xmas(pcap)
    stealth_scans(pcap)
    print("Saved Reccomended Rules for SNORT to file named SNORT_Rules.txt")
    print("Saved Reccomended Rules for UFW to file name UFW_Rules.txt")

def open_directory():
    files = sys.argv[2]
    files=glob.glob(f'{files}/*.pcap*')
    files = sorted(files)
    for x in files:
        dos(x)
        ping(x)
        SYN_DOS(x)
        xmas(x)
        stealth_scans(x)
        print("Saved Rule Suggestions to SNORT_Rules.txt, and UFW_Rules.txt")



def Main():
    parser = argparse.ArgumentParser(description="An Automatic Snort/UFW rule suggestor")
    group= parser.add_mutually_exclusive_group()
    parser.add_argument("-n", "--network", action='store_true', help='captures network traffic')
    parser.add_argument('-r','--read', type=open,help='Reads a PCAP file')
    parser.add_argument('-d','--directory',nargs='+',help='Opens and reads through a directory of pcaps')
    parser.add_argument('-e', '--extension', default='', help='File extension to filter by.')
    args = parser.parse_args()

    if args.network:
        network_capture()
    elif args.read:
        open_pcap()
    elif args.directory:
        open_directory()
    else:
        print('Please select argument -n,-r, or -d')

if __name__=='__main__':
    Main()

