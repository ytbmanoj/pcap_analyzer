
import json
import logging
from fastapi import APIRouter, Header, Response, status
from fastapi import FastAPI, File, UploadFile
from util.pcapAnalyser import analyzeFile
from multiprocessing import Process, Queue
import nest_asyncio
nest_asyncio.apply()

pcapParser = APIRouter()

@pcapParser.post("/analyze")
async def list_asset(response: Response, pcapfile: UploadFile):
    
    file_location = f"../uploads/{pcapfile.filename}"
    with open(file_location, "wb+") as file_object:
        file_object.write(pcapfile.file.read())
    
    pcap_queue = Queue()
    pcap_process = Process(target=analyzeFile, args=(file_location, ))
    pcap_process.start()
    pcap_process.join()

    ip_array=[]
    with open("../results/sample.json", "r") as outfile:
        for line in outfile:
            data = json.loads(line)
            ip_array.append(data)
        
    print(ip_array)
    return ip_array