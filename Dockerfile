FROM ubuntu:21.04

RUN apt-get update && apt-get install -y xinetd

RUN useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf
WORKDIR /home/ctf

COPY ctf.xinetd /etc/xinetd.d/ctf
RUN chmod 644 /etc/xinetd.d/ctf

COPY admin_panel /home/ctf/admin_panel
COPY start.sh /home/ctf/start.sh
COPY flag.txt /flag.txt

RUN chown -R root:ctf /home/ctf
RUN chmod -R 750 /home/ctf
RUN chown root:ctf /flag.txt
RUN chmod 640 /flag.txt
USER ctf

CMD /home/ctf/start.sh
EXPOSE 9999
