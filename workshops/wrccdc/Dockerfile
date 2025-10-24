FROM ubuntu:22.04
ARG USERNAME="ping"

RUN apt-get update && apt-get -y install cron vim nano sudo

# Create users and add to sudo group
RUN useradd -m -u 1001 -s /bin/bash -G sudo $USERNAME
RUN useradd -m -u 1002 -s /bin/bash -G sudo norm 

# Remove password for root
RUN passwd -d root
RUN passwd -d ping

# Change ping's alias to ls to output norm.txt
COPY norm.txt /opt/
RUN echo 'alias ls="cat /opt/norm.txt"' >> /home/ping/.bashrc

# Added cronjob
COPY not_malware.exe /root/
RUN chmod +x /root/not_malware.exe
RUN echo "* * * * * root /root/not_malware.exe &" > /etc/cron.d/not_malware
RUN chmod 0644 /etc/cron.d/not_malware
RUN crontab /etc/cron.d/not_malware

# Removing sudo message
RUN touch /home/ping/.sudo_as_admin_successful

WORKDIR /home/ping

ENTRYPOINT cron -f
