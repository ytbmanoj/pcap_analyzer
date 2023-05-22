
import logging
import sys
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from routes.analyzePcap import pcapParser
from routes.portScanner import portScanner
from routes.phoneinfoga import phoneinfoga
import nest_asyncio
nest_asyncio.apply()
from fastapi.middleware.cors import CORSMiddleware

origins = ["*"]

app = FastAPI()

app.include_router(pcapParser)
app.include_router(portScanner)
app.include_router(phoneinfoga)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_request: Request, _exc: RequestValidationError):
    """ Request validation error """
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content="Request contains invalid data",
    )


@app.get("/", tags=["Root"], include_in_schema=True)
def hello_world():
    """Default route"""
    return "Welcome to VoIP hunter"



