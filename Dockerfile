FROM ubuntu:14.04
MAINTAINER Bob Van Zant <bob@veznat.com>
LABEL Description="up-to-date ubuntu environment" Vendor="Cloudtools"

RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git-core

LABEL Description="up-to-date golang environment"

RUN mkdir -p /build

ENV GOROOT=/build/go-build/go
ENV PATH=/build/go-build/go/bin:/usr/local/bin:/usr/bin:/bin

RUN mkdir -p /build/go-build; \
    cd /build/go-build; \
    curl -s https://storage.googleapis.com/golang/go1.4.2.src.tar.gz | tar -zxf -; \
    cd /build/go-build/go/src; \
    GOOS=darwin GOARCH=amd64 ./make.bash --no-clean 2>&1 > /dev/null ;


LABEL Description="ssh-cert-authority builder"

ENV GOPATH=/build/ssh-cert-authority/go
RUN mkdir -p $GOPATH/src/github.com/cloudtools/ssh-cert-authority
WORKDIR $GOPATH/src/github.com/cloudtools/ssh-cert-authority
