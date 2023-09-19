FROM python:3.11-alpine

RUN apk update && apk add gcc musl-dev && apk add --no-cache bash coreutils grep sed busybox-extras && ntpd -q -p time.google.com

WORKDIR /app

COPY . .

RUN pip install -U pip tzdata && pip install -r requirements.txt && chmod +x ./init.sh 

ENTRYPOINT ./init.sh
