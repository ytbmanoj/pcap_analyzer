FROM ubuntu:20.04
RUN apt-get update && apt-get install -y python3.9 python3.9-dev && apt-get install -y python3-pip && apt-get install nmap -y
ENV DEBIAN_FRONTEND noninteractive
ENV DEBCONF_NONINTERACTIVE_SEEN true
RUN apt-get install tshark -y
COPY . .
RUN python3.9 -m pip install -r requirements.txt
WORKDIR /app/src
CMD ["python3.9","-m","uvicorn","main:app","--port","8000", "--host","0.0.0.0"]