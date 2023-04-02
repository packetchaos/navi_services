FROM ubuntu:latest

RUN apt-get update && apt-get install -y python3-pip && rm -rf /var/lib/apt/lists/*
RUN pip3 install flask && pip3 install requests && pip3 install pytenable && pip3 install navi-pro

CMD mkdir /usr/src/app
CMD mkdir /usr/src/app/templates
CMD mkdir /usr/src/app/static/styles

VOLUME ["/usr/src/app/"]
 
ADD portal.py /usr/src/app/
ADD database.py /usr/src/app/
ADD dbconfig.py /usr/src/app/
ADD dynamic_rules.py /usr/src/app/
ADD keys.py /usr/src/app/
ADD update.py /usr/src/app/
ADD api_wrapper.py /usr/src/app/
ADD update.py /usr/src/app/
ADD templates/index.html /usr/src/app/templates/
ADD templates/navi_gate.html /usr/src/app/templates/
ADD templates/scan_stats.html /usr/src/app/templates/
ADD templates/tagging.html /usr/src/app/templates/
ADD templates/sla_stats.html /usr/src/app/templates/
ADD templates/results.html /usr/src/app/templates/
ADD static/css/navi.css /usr/src/app/static/css/

ENV PATH "$PATH:/usr/bin/env/:/usr/src/app"

EXPOSE 5000

WORKDIR /usr/src/app/data

CMD python3 /usr/src/app/portal.py
