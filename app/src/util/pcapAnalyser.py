import pyshark
import re
import json
import subprocess
import sys
import asyncio
import nest_asyncio
import requests
nest_asyncio.apply()

l=[]
var_list=['query','countryCode','country','dateTime','regionCode','region','regionName','city','zip','timeZone','isp','org','as','latitude','longitude','location']

def is_ip_private(ip):

    priv_lo = re.compile("^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    priv_24 = re.compile("^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    priv_20 = re.compile("^192\.168\.\d{1,3}.\d{1,3}$")
    priv_16 = re.compile("^172.(1[6-9]|2[0-9]|3[0-1]).[0-9]{1,3}.[0-9]{1,3}$")

    res = priv_lo.match(ip) or priv_24.match(ip) or priv_20.match(ip) or priv_16.match(ip)

    if not res:
        return False
    return True

def match_organization(out_dict):
    # print (out_dict)
    organization = out_dict['org']

    if re.match(r"[A-Z]*Facebook[A-Z]*", organization):
        return True
    if re.match(r"[A-Z]*facebook[A-Z]*", organization):
        return True
    if re.match(r"[A-Z]*Google[A-Z]*", organization):
        return True
    if re.match(r"[A-Z]*meta[A-Z]*", organization):
        return True
    if re.match(r"[A-Z]*Meta[A-Z]*", organization):
        return True
    
    return False

def format_string(out_dict, time):
    
    # ansi_escape = re.compile(r'''
    #     \x1B  
    #     (?:   
    #         [@-Z\\-_]
    #     |    
    #         \[
    #         [0-?]*  
    #         [ -/]*  
    #         [@-~]   
    #     )
    # ''', re.VERBOSE)
    # result = ansi_escape.sub('', out.decode())
    # result= result[340:]
    # result=result.split('>')

    # formatted_list = []

    # for i in range(len(result)):
    #     if '\n' in result[i]:
    #         res= result[i].strip().split('\n')
    #         for ele in res:
    #             formatted_list.append(ele.strip())
    #     else:
    #         formatted_list.append(result[i].strip())
    # out_dict={}
   
    # i=0
    # while(i<len(formatted_list)-1):
    #     left=var_list[i//2]
    #     right=formatted_list[i+1]
    #     out_dict[left]=right
    #     i=i+2
    try:
        result_dict={}
        result_dict['ipAddr'] = out_dict['query']
        result_dict['isp'] = out_dict['isp']
        result_dict['organization'] = out_dict['org']
        result_dict['asn'] = out_dict['as']
        result_dict['latitude'] = out_dict['lat']
        result_dict['longitude'] = out_dict['lon']
        result_dict['country'] = out_dict['country']
        result_dict['region'] = out_dict['region']
        result_dict['city'] = out_dict['city']
        result_dict['zipCode'] = out_dict['zip']
        result_dict['dateTime'] = str(time)
        if(not match_organization(out_dict)):
            l.append(result_dict)
            print(result_dict)
    except:
        l.append(out_dict)
        pass
    return


def appendIPtoJSON(ip_address, time):
    if not is_ip_private(ip_address):
        
        # proc = subprocess.Popen('wsl ip-tracer -t {}'.format(ip_address), shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        # out, err = proc.communicate()   
        url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(url)
        #print(response.json())
        format_string(response.json(),time ) 


def analyzeFile(filepath):

    capture = pyshark.FileCapture(filepath)
    previous_queries={}
    count=0
    for packet in capture:
        if 'stun' in packet and 'IPV6' in packet:
            source_adress=packet['IPV6'].src
            destination_adress=packet['IPV6'].dst

            if(source_adress not in previous_queries):
                previous_queries[source_adress]=1
                appendIPtoJSON(source_adress, packet.sniff_time)
            if(destination_adress not in previous_queries):
                previous_queries[destination_adress]=1
                appendIPtoJSON(destination_adress, packet.sniff_time)
            
        if 'stun' in packet and 'IP' in packet:
            source_adress=packet['IP'].src
            destination_adress=packet['IP'].dst  

            if(source_adress not in previous_queries):
                previous_queries[source_adress]=1
                appendIPtoJSON(source_adress, packet.sniff_time)
            if(destination_adress not in previous_queries):
                previous_queries[destination_adress]=1
                appendIPtoJSON(destination_adress, packet.sniff_time)

        count+=1
        if(count%100==0):
            print("so far packets analysed ",count)

    with open("./../results/sample.json", "w") as outfile:
        for out_dict in l:
            json.dump(out_dict, outfile)
            outfile.write('\n')



if __name__ == "__main__":
    analyzeFile("./PCAPdroid_27_Feb_23_54_51.pcap")