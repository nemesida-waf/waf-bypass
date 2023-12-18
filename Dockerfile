FROM debian:12.2

WORKDIR /opt/waf-bypass

RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install python3 python3-pip python3-venv python3-dev
RUN mkdir -p /opt/waf-bypass

COPY . .

RUN rm -rf /opt/waf-bypass/venv; python3 -m venv /opt/waf-bypass/venv
RUN /opt/waf-bypass/venv/bin/python3 -m pip install -r /opt/waf-bypass/requirements.txt
RUN chmod +x /opt/waf-bypass/main.py

ENTRYPOINT ["/opt/waf-bypass/venv/bin/python3", "/opt/waf-bypass/main.py"]
