FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y socat libc6 gcc gdb && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /chall

COPY ./hothothot/run.sh /run.sh
COPY ./hothothot/hothothot .
COPY ./hothothot/flag.txt .
RUN mkdir -p ./glibc
COPY ./hothothot/glibc/* ./glibc/

RUN sed -i 's/\r//' /run.sh

RUN chmod 444 flag.txt && \
    chmod +x /run.sh && \
    chmod +x /chall/hothothot

CMD ["/bin/sh", "/run.sh"]