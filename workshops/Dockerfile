FROM ubuntu:22.04
ARG USERNAME="scott"

RUN useradd -m -u 1001 -s /bin/sh $USERNAME
RUN useradd -m -u 1002 -s /usr/sbin/nologin ian 

COPY readme.txt /home/scott/ 
COPY todo.txt /home/ian/
COPY password.txt /home/ian/

RUN chmod 477 /home/ian

USER $USERNAME
