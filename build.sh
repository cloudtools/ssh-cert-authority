#!/bin/bash -e

go get
go test ./...

ARCHITECTURES=amd64
OPERATING_SYSTEMS="linux darwin"
for GOARCH in $ARCHITECTURES; do
    for GOOS in $OPERATING_SYSTEMS; do
        go build -o ssh-cert-authority-$GOOS-$GOARCH
        gzip -f ssh-cert-authority-$GOOS-$GOARCH
    done
done
