FROM ubuntu:20.04
RUN apt-get update && apt-get install -y python3 && apt-get install -y python3-pip && apt-get install -y locales
RUN rm -rf /var/lib/apt/lists/*
RUN localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
RUN pip3 install requests
RUN pip install click
RUN pip install pytenable
RUN pip install navi-pro
ENV LANG en_US.utf8

ENV PATH "$PATH:/usr/bin/env/:/usr/src/app"

ENV access_key=$access_key

ENV secret_key=$secret_key

COPY advanced_tags.py /usr/src/app/

COPY tvm_example.xlsx /usr/src/app/

WORKDIR /usr/src/app

RUN chmod +x advanced_tags.py

CMD ["python3", "./advanced_tags.py", "$access_key", "$secret_key"]
