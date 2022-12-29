FROM debian:11.6

RUN apt update -y && apt upgrade -y; apt install -y python3 python3-pip python3-venv python3-dev
RUN mkdir /opt/waf-bypass

WORKDIR /opt/waf-bypass

COPY . .

RUN python3 -m pip install -r /opt/waf-bypass/requirements.txt
RUN chmod +x /opt/waf-bypass/main.py

ENTRYPOINT ["/opt/waf-bypass/main.py"]
