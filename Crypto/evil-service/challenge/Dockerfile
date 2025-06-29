FROM ubuntu:latest

RUN apt-get update && apt-get install socat -y && apt-get install python3 -y

WORKDIR /app

COPY src/main.py .
COPY src/secret.py .
COPY entry.sh .

RUN chmod +x entry.sh

CMD ["./entry.sh"]