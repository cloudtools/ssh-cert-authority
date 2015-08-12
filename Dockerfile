FROM ubuntu:14.04
MAINTAINER Bob Van Zant <bob@veznat.com>
LABEL Description="ssh-cert-authority"
COPY ssh-cert-authority-linux-amd64.gz /usr/local/bin/ssh-cert-authority.gz
RUN gunzip /usr/local/bin/ssh-cert-authority.gz
RUN chmod +x /usr/local/bin/ssh-cert-authority
RUN apt-get update
RUN apt-get install -y openssh-client
ENTRYPOINT ["ssh-agent", "/usr/local/bin/ssh-cert-authority", "runserver"]
