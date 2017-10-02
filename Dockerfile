FROM ubuntu:16.04
MAINTAINER Bob Van Zant <bob@veznat.com>
LABEL Description="ssh-cert-authority"
RUN apt-get update && apt-get install -y openssh-client && apt-get clean && rm -rf /var/lib/apt
COPY ssh-cert-authority-linux-amd64.gz /usr/local/bin/ssh-cert-authority.gz
RUN gunzip /usr/local/bin/ssh-cert-authority.gz
RUN chmod +x /usr/local/bin/ssh-cert-authority
ENTRYPOINT ["ssh-agent", "/usr/local/bin/ssh-cert-authority", "runserver"]
