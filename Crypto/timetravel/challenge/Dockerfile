FROM ubuntu:18.04

RUN apt-get update && apt-get install socat -y && apt-get install python3 -y

WORKDIR /app

COPY main.py .
COPY secret.py .
COPY entry.sh .

RUN chmod +x entry.sh

CMD ["./entry.sh"]