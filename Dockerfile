FROM python:3-alpine3.13

COPY . /srv/AlarmServer

RUN adduser -D -u 1000 alarm &&\
    pip install -r /srv/AlarmServer/requirements.txt

USER alarm

EXPOSE 8111/tcp 4025/tcp

CMD ["/usr/local/bin/python", "/srv/AlarmServer/alarmserver.py", "-c", "/config/alarmserver.cfg"]
