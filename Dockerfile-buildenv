FROM ubuntu:16.04
MAINTAINER Bob Van Zant <bob@veznat.com>
LABEL Description="up-to-date ubuntu environment" Vendor="Cloudtools"

RUN apt-get update && \
    apt-get install -y \
        build-essential \
        curl \
        git-core && \
    apt-get clean && \
    rm -rf /var/lib/apt

LABEL Description="up-to-date golang environment"

RUN mkdir -p /build  \
    && curl -O https://storage.googleapis.com/golang/go1.9.linux-amd64.tar.gz \
    && echo "d70eadefce8e160638a9a6db97f7192d8463069ab33138893ad3bf31b0650a79 go1.9.linux-amd64.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf go1.9.linux-amd64.tar.gz \
    && rm -f go1.9.linux-amd64.tar.gz

ENV GOROOT_BOOTSTRAP=/usr/local/go
ENV GOROOT=/build/go-build/go
ENV PATH=/build/go-build/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/go/bin

RUN mkdir -p /build/go-build \
    && cd /build/go-build \
    && curl -o go.tar.gz -s https://storage.googleapis.com/golang/go1.9.src.tar.gz \
    && echo "a4ab229028ed167ba1986825751463605264e44868362ca8e7accc8be057e993 go.tar.gz" | sha256sum -c - \
    && tar -zxf go.tar.gz \
    && cd /build/go-build/go/src \
    && GOOS=darwin GOARCH=amd64 ./make.bash --no-clean 2>&1 > /dev/null ;

LABEL Description="ssh-cert-authority builder"

ENV GOPATH=/build/ssh-cert-authority/go
RUN mkdir -p $GOPATH/src/github.com/cloudtools/ssh-cert-authority
WORKDIR $GOPATH/src/github.com/cloudtools/ssh-cert-authority
