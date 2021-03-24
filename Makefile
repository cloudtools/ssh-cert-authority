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

ssh-cert-authority-linux-arm64:
	GOOS=linux GOARCH=arm64 \
		 go build -o ssh-cert-authority-linux-arm64 \
		 	-ldflags "-X ${PKG}/version.Tag=${TAG} -X ${PKG}/version.BuildVersion=${VERSION}" .

ssh-cert-authority-linux-arm64.gz: ssh-cert-authority-linux-arm64
	gzip -f ssh-cert-authority-linux-arm64

ssh-cert-authority-linux-arm7:
	GOOS=linux GOARCH=arm7 \
		 go build -o ssh-cert-authority-linux-arm7 \
		 	-ldflags "-X ${PKG}/version.Tag=${TAG} -X ${PKG}/version.BuildVersion=${VERSION}" .

ssh-cert-authority-linux-arm7.gz: ssh-cert-authority-linux-arm7
	gzip -f ssh-cert-authority-linux-arm7

ssh-cert-authority-darwin-amd64:
	GOOS=darwin GOARCH=amd64 \
		 go build -o ssh-cert-authority-darwin-amd64 \
		 	-ldflags "-X ${PKG}/version.Tag=${TAG} -X ${PKG}/version.BuildVersion=${VERSION}" .

ssh-cert-authority-darwin-amd64.gz: ssh-cert-authority-darwin-amd64
	gzip -f ssh-cert-authority-darwin-amd64

ssh-cert-authority-darwin-arm64:
	GOOS=darwin GOARCH=arm64 \
		 go build -o ssh-cert-authority-darwin-arm64 \
		 	-ldflags "-X ${PKG}/version.Tag=${TAG} -X ${PKG}/version.BuildVersion=${VERSION}" .

ssh-cert-authority-darwin-arm64.gz: ssh-cert-authority-darwin-arm64
	gzip -f ssh-cert-authority-darwin-arm64

release: ssh-cert-authority-darwin-amd64.gz ssh-cert-authority-darwin-arm64.gz ssh-cert-authority-linux-amd64.gz ssh-cert-authority-linux-arm64.gz ssh-cert-authority-linux-arm7

test:
	@go test ./...

vet:
	@go vet ./...

