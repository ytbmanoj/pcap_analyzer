

import nmap
import json
import logging
from fastapi import APIRouter, Header, Response, status
from fastapi import FastAPI, File, UploadFile
from multiprocessing import Process, Queue

portScanner = APIRouter()

@portScanner.get("/portscan")
async def portscan(response: Response, ipaddress:str):
    nm = nmap.PortScanner()

    # Specify the target IP address to scan
    target_ip = ipaddress
    # Set the options for the scan
    scan_options = "-A -O -sV"
    # Run the nmap scan with the specified options on the target IP address
    data = nm.scan(hosts=target_ip, arguments=scan_options)

    print("Scanning ...", data)
    # Print the scan results
    scan_info = nm.scaninfo()
    print(scan_info)
    print(nm.all_hosts())
    print(nm[target_ip].all_tcp())
    print(nm.scanstats())

    scan_result = []

    # Print the scan results
    print("Nmap scan summary:")
    print(nm.scaninfo())
    print("")

    result = []
    for host in nm.all_hosts():
        print("Host: %s" % host)
        print("Status: %s" % nm[host].state())
        if 'osmatch' in nm[host]:
            os = nm[host]['osmatch'][0]['name']
        else:
            os = "Not Found"

        # Print the port information
        if 'tcp' in nm[host]:
            port_list = []
            for port in nm[host]['tcp']:
                if 'state' in nm[host]['tcp'][port]:
                    state = {"State": nm[host]['tcp'][port]['state']}
                if 'name' in nm[host]['tcp'][port]:
                    service = {"Service": nm[host]['tcp'][port]['name']}
                port_info = {port: [state, service]}
                port_list.append(port_info)
        
        result.append({"host": host, "status":nm[host].state(), "OS":os, "port":port_list })
        
    return result
    