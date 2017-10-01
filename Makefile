TAG?=1.6.1
VERSION := $(shell echo `git describe --tags --long --match=*.*.* --dirty` | sed s/version-//g)

PKG=github.com/cloudtools/ssh-cert-authority

test:
	go test ./...

vet:
	go vet ./...

all: test
	go build -ldflags "-X ${PKG}/version.Tag=${TAG} -X ${PKG}/version.BuildVersion=${VERSION}" .
