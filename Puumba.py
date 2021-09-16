#!/usr/bin/python3
import subprocess
import sys
import argparse
import re


def network_capture():
    cmd =['tcpdump', '-w', 'traffic.pcap']#our command

    f = open('traffic.pcap', 'w') #this creates the file

    subprocess.run(cmd)#this sends it to f

host_IP = subprocess.check_output(['hostname', '--all-ip-addresses'])
host_IP=host_IP.split()
host_IP2=[]
for ip in host_IP:
    ip = ip.decode()
    host_IP2.append(ip)



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
            # print(IP_set)
            if i not in host_IP2:
                for ip in host_IP2:
                    n = snort.write(f'Alert ICMP {i} any -> {ip} (sid:1000002; MSG:"PING SCAN")\n')#makes the snort rule
        snort.close()
        ufw = open('UFW_Rules.txt','a+')#opens new file, saves reccomended UFW rules
        for i in IP_set:
            if i not in host_IP2:
                for ip in host_IP2:
                    u = ufw.write(f'sudo ufw deny from {i}\n')
        ufw.close()
    else:
        print("This file contains no ICMP traffic")


def DOS(pcap):
    IP_list=[]
    src_ip=[]
    timestamps=[]
    tshark_traffic=subprocess.check_output(['tshark','-r',pcap,'-Y','tcp.flags.syn==1 and tcp.flags.ack==0']).decode("utf-8")
    tshark_traffic = tshark_traffic.split('\n')
    for line in tshark_traffic:
        strings = line.split()
        if len(strings) != 0:
            timestamps.append(strings[2])#make a list of all time stamps so we can compare them
            if '[SYN]' in strings:
                IP_list +=re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} →',line)
            for i in IP_list:
                i=i.replace(' →','')
                src_ip.append(i)
    src_ip=sorted(src_ip)
    compare = {}
    for i in src_ip:
        if i not in host_IP2:
            if i in compare.keys():
                compare[i]+=1
            else:
                compare[i]=0
    for ip, count in compare.items():                
        if  count >= 200:
            for i in host_IP2:
                snort = open('SNORT_Rules.txt','a+')
                n = snort.write(f'Alert any {ip} any -> {i} (sid:1000003; MSG:"POSSIBLE DDOS ATTACK")\n')
                ufw = open('UFW_Rules.txt','a+')
                u = ufw.write(f'sudo ufw deny from {ip}\n')
                snort.close()
                ufw.close()

def open_pcap():
    pcap=sys.argv[2]
    # ping(pcap)
    DOS(pcap)
def Main():
    parser = argparse.ArgumentParser(description="An Automatic Snort/UFW rule suggestor")
    group= parser.add_mutually_exclusive_group()
    parser.add_argument("-n", "--network", action='store_true', help='captures network traffic')
    parser.add_argument('-r','--read', type=open,help='Reads a PCAP file')
    args = parser.parse_args()

    if args.network:
        network_capture()
    elif args.read:
        open_pcap()
    else:
        print('Please select argument -n to start a network capture, or -r to read an already saved pcap.')

if __name__=='__main__':
    Main()

