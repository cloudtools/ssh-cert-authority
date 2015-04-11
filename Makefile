
ALL=request_cert sign_cert sign_certd get_cert

all: $(ALL)

.PHONY: test clean
test:
	cd client && go test

clean:
	rm -f $(ALL)

request_cert:
	go build request_cert.go

sign_cert:
	go build sign_cert.go

sign_certd:
	go build sign_certd.go

get_cert:
	go build get_cert.go
