# ssh-ca-ss
Self service version of SSH-CA this time written in Go

Operators of ssh-ca-ss want to use SSH certificates to provide fine-grained access control to servers they operate, keep their certificate signing key a secret and not need to be required to get involved to actually sign certificates. A tall order.

The idea here is that a user wishing to access a server runs the request_cert utility and specifies a few parameters for the cert request like how long he/she wants it to be valid for. This is POSTed to the sign_certd daemon which validates that the certificate request was signed by a valid user (configured on the daemon side) before storing a little state and returning a certificate id to the requester.

The requester then convinces one or more of his or her authorized friends (who are authorized and the number required is configured on the daemon side) to run the sign_cert utility specifying the request id. The signer is allowed to see the parameters of the certificate before deciding whether or not to actually sign the cert request. The signed certificate is again POSTed back to the sign_certd daemon where the signature is validated.

Once enough valid signatures are received the cert request is automatically signed using the signing key for the cert authority and made available for download by the requester using the request id.

None of the code here ever sees or even attempts to look at secrets. All signing operations are performed by ssh-agent. In order to bootstrap the signing daemon you must ssh-add the signing key. In order to request a cert or sign someone's cert request the user must have the key used for signing loaded up in ssh-agent. Secrets are really hard to keep, we'll leave them in the memory space of ssh-agent.

[![Build Status](https://drone.io/github.com/bobveznat/ssh-ca-ss/status.png)](https://drone.io/github.com/bobveznat/ssh-ca-ss/latest)
