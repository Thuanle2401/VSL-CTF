FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash pwn

WORKDIR /home/pwn

COPY src/magic_trick /home/pwn/magic_trick
COPY src/flag.txt /home/pwn/flag.txt
COPY src/glibc/ /home/pwn/glibc/

RUN chmod +x /home/pwn/magic_trick
RUN chmod 644 /home/pwn/flag.txt
RUN chmod 755 /home/pwn/glibc/
RUN chmod 755 /home/pwn/glibc/ld-linux-x86-64.so.2
RUN chmod 755 /home/pwn/glibc/libc.so.6

RUN chown -R pwn:pwn /home/pwn

USER pwn

EXPOSE 1337

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/home/pwn/magic_trick,pty,stderr"] 