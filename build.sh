#!/bin/bash -e

go get
make test ssh-cert-authority-linux-amd64.gz ssh-cert-authority-darwin-amd64.gz

