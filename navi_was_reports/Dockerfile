FROM ubuntu:20.04
RUN apt-get update && apt-get install -y python3 && apt-get install -y python3-pip && apt-get install -y locales
RUN rm -rf /var/lib/apt/lists/*
RUN localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
RUN pip install requests
RUN pip install click
RUN pip install pytenable
RUN pip install navi-pro
ENV LANG en_US.utf8
ENV access_key=$access_key
ENV secret_key=$secret_key
RUN mkdir /usr/src/app
RUN mkdir /usr/src/app/templates
ENV PATH "$PATH:/usr/bin/env/:/usr/src/app"
COPY /templates/ /usr/src/app/templates/
COPY was_report_gen.py /usr/src/app/
COPY dbconfig.py /usr/src/app/
EXPOSE 5004
WORKDIR /usr/src/app
CMD python3 ./was_report_gen.py $access_key $secret_key
