FROM ubuntu:latest

RUN apt-get update && apt-get install -y python3-pip && apt-get install -y netcat && apt-get install -y locales && rm -rf /var/lib/apt/lists/* \
	&& localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
RUN pip3 install requests && pip3 install click && pip3 install IPy && pip3 install pytenable && pip3 install pandas && pip3 install navi-pro

ENV LANG en_US.utf8

ENV PATH "$PATH:/usr/bin/env/:/usr/src/app"

ENV access_key=$access_key

ENV secret_key=$secret_key

COPY deploy_all.py /usr/src/app/

WORKDIR /usr/src/app

RUN chmod +x deploy_all.py

CMD ["python3", "./deploy_all.py", "$access_key", "$secret_key"]
