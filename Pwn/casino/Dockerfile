FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    socat libc6 \
    && rm -rf /var/lib/apt/lists/* 

RUN useradd -m -s /bin/bash pwn

WORKDIR /home/pwn

COPY task /home/pwn/

RUN chown -R root:pwn /home/pwn && \
    chmod 750 /home/pwn && \
    chmod 550 /home/pwn/task

USER pwn

EXPOSE 1337

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:./task 