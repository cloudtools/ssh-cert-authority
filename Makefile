TAG?=2.0.0
VERSION := $(shell echo `git describe --tags --long --match=*.*.* --dirty` | sed s/version-//g)

PKG=github.com/cloudtools/ssh-cert-authority

.PHONY: test vet

ssh-cert-authority:
	go build -ldflags "-X ${PKG}/version.Tag=${TAG} -X ${PKG}/version.BuildVersion=${VERSION}" .

ssh-cert-authority-linux-amd64:
	GOOS=linux GOARCH=amd64 \
		 go build -o ssh-cert-authority-linux-amd64 \
		 	-ldflags "-X ${PKG}/version.Tag=${TAG} -X ${PKG}/version.BuildVersion=${VERSION}" .

ssh-cert-authority-linux-amd64.gz: ssh-cert-authority-linux-amd64
	gzip -f ssh-cert-authority-linux-amd64

ssh-cert-authority-darwin-amd64:
	GOOS=darwin GOARCH=amd64 \
		 go build -o ssh-cert-authority-darwin-amd64 \
		 	-ldflags "-X ${PKG}/version.Tag=${TAG} -X ${PKG}/version.BuildVersion=${VERSION}" .

ssh-cert-authority-darwin-amd64.gz: ssh-cert-authority-darwin-amd64
	gzip -f ssh-cert-authority-darwin-amd64

release: ssh-cert-authority-darwin-amd64.gz ssh-cert-authority-linux-amd64.gz

test:
	@go test ./...

vet:
	@go vet ./...

