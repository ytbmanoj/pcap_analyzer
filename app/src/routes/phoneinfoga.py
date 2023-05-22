

import nmap
import json
import logging
from fastapi import APIRouter, Header, Response, status
from fastapi import FastAPI, File, UploadFile
from multiprocessing import Process, Queue
import requests
phoneinfoga = APIRouter()

@phoneinfoga.get("/phoneinfoga")
async def portscan(response: Response, phoneNumber:str):
    url="https://demo.phoneinfoga.crvx.fr/api/numbers/"+phoneNumber+'/scan/googlesearch'
    headers = {
        "Authorization": "Bearer your_access_token",
        "Content-Type": "application/json"
    }
    result = requests.get(url, headers=headers)
    print(result.json())
    return result.json()
    