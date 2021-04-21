#!/usr/bin/env python3
#=====================
import socket
import re
import nmap
import ipaddress
import sys
import random
import pandas as pd
import time
from datetime import datetime, timedelta

def main():

    runtime = 0

    while True:

        if runtime < 86400: #if script has been running < 24hrs
            ip_range = get_range() #run get_range() funciton to identify IP space
            scan_results = scan_space(ip_range) #pass returned IP range to scan_space() funciton
            new_host_count = record(scan_results) #pass results of scan to record() function

            #run script @ random periods of time throughout the runtime
            interval = random.randrange(60, 120) #create random interval b/w 1-5 mins
            now = datetime.now().replace(microsecond=0)
            next = now + timedelta(0,interval)
            print(f'{now} Scan success, new hosts detected on {ip_range}: {new_host_count} , next scan at {next}')
            runtime += interval #cumulative runtime
            time.sleep(interval) #sleep the lenght of the interval

        elif runtime > 86400: #terminate the script if runtime > 24hrs
            sys.exit('Total runtime parameter exceeded!')

def get_range(): #get the target\ IP range to be scanned

    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)

    #check if the ip_address in space allocated for pirvate networks
    if ipaddress.IPv4Address(ip_address).is_private == False:
        #kill program to avoid scanning public IP addresses
        sys.exit('Not private IP space, dont scan!')

    else: #create target IP range
        #assumes private IP space behind home router is xxx.xxx.xxx.0/24
        #get the base IPv4 of the private IP space
        match = re.findall(r'[0-2]?\d?\d\.[0-2]?\d?\d\.[0-2]?\d?\d\.', ip_address)
        base_IP = match[0]
        #create a range from that base
        ip_range = base_IP+'0-255' #nmap modules can also accept CIDR notation

    return(ip_range) #pass target range back to main()

def scan_space(ip_addr): #scan the target IP space for active hosts

    nm = nmap.PortScanner() #define nmap portscaner class

    #default host discovery:ICMP echo, TCP SYN p443, TCP ACK p80, & ICMP timestamp req
    #when scanning within private IP space; -sn defaults to ARP requests
    scan_results = nm.scan(hosts=ip_addr, arguments='-sn' , sudo=True)

    return(scan_results)

def record(scan_results): #record unique results to the finds.csv file

  #generate a pandas df from the finds.csv file
  df = pd.read_csv('/Users/erik/Documents/Projects/Python/securityResearch/portIP_scanner/watchDog/finds.csv')

  #create a list of all 'up hosts' discovered in scan_results
  up_hosts = scan_results['scan'] #get a list of all the 'up hosts'
  new_host_count = 0 #initalize a count of new hosts discovered as 0

  for k,v in up_hosts.items(): #keys are strings, values are dicts

    mac = v['addresses'].get('mac')#get the mac address of that host

    if mac in df.values or mac == None: #check if that mac is already in finds.csv
        continue
    elif mac not in df.values: #check if this is a new mac address
        new_host_count += 1
        new_line = {
            'mac':mac,
            'ipv4':k,
            'vendor':v.get('vendor'),
            'scanstats':scan_results['nmap'].get('scanstats'),
            'status':v.get('status'),
            'command_line':scan_results['nmap'].get('command_line'),
            'identity':'unknown'
            }

        #append that new record to the data frame
        df = df.append(new_line, ignore_index=True)

    df.to_csv('/Users/erik/Documents/Projects/Python/securityResearch/portIP_scanner/watchDog/finds.csv', index=False) #convert updated df back to csv

    return(new_host_count)

if __name__ == "__main__": main() #enable forward decleration
