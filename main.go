package main

import (
    "os"
    "path"
)

func main() {
    programName := path.Base(os.Args[0])
    if programName == "sign_cert" {
        signCert()
    } else if programName == "sign_certd" {
        signCertd()
    } else if programName == "request_cert" {
        requestCert()
    } else if programName == "get_cert" {
        getCert()
    }
}
