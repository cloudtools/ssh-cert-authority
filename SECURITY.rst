==============
Security Model
==============

This document attempts to describe the threats that ssh-cert-authority
is designed to cope with and how or why it meets them.

-------
Threats
-------

Against ssh-cert-authority
==========================

It is recommended that the daemon be configured to run in a secure
network location accessible to a minimal set of networks.

It is recommended that the daemon be configured to run over a current
version of TLS using valid certificates.

Disclosure of the private key
-----------------------------

The private key of the cert authority must be kept secret at all times.
A compromise of the key allows an attacker to sign any certificate and
gain access to other systems.

The ssh-cert-authority daemon does not have access to the private key at
any time. We rely on the security of the ssh-agent daemon to keep the
key as secure as possible (given that its simply sitting in memory).

It is recommended that the ssh-cert-authority and corresponding
ssh-agent daemon be run using an unprivileged service account that is
not shared by other services on the same machine.

It may be possible, especially with security focused kernels, to set
ACLs on the ssh-agent socket that only allow the pid of the
ssh-cert-authority daemon to connect to it.

Sign certificate of an attacker
-------------------------------

The ssh-cert-authority daemon must not accept the submission of requests
from unauthorized users or signers.

Authorized users and signers are configured in a json file sitting on
the same server as the daemon. Were an attacker able to modify this file
or simply the configuration information stored in the currently running
daemon they could become an authorized user or signer.

The ssh-cert-authority must defend against an attacker submitting
signatures on either requests or signing commands using keys that are
not in the config.

Unauthorized user submits signature for request
-----------------------------------------------

Including:
    cross-environment tweaks (request from one env signed by signer from
    a different one?)

Against users
=============

Private key compromise
----------------------

Users of this service must keep their private key file a secret. A
compromised user key allows an attacker to submit cert requests (or
signing commands) on behalf of the compromised key.

------
Design
------

The ssh-cert-authority daemon is an HTTP service that by default listens
on port 8080.

It uses json files for configuration. Configuration information includes
sets of both authorized users and authorized signers that are identified
by SSH key fingerprints. In addition the fingerprint of the signing key
(the cert authority's key) is stored in configuration.

Users are able to request certificates from the system.

Signers are able to +1 requests.

A certificate that has been +1'ed by the requisite number of people is
signed by a local ssh-agent process. This means that the secret key for
signing certificates is never stored or even made visible to the
ssh-cert-authority daemon.

Users are authenticated by signing requests for certificates and +1
commands with their own SSH private key.

Cert requests and signing commands are done using actual SSH
certificates. This ensures that the entire block of relevant information
is included in the signature that is being verified by the server.

For example, an end to end request and sign:

- Requester generates and signs a complete SSH certificate specifying parameters
  like lifetime and valid principals.
- Server verifies that the certificate is valid and that it was signed
  by a user in the AuthorizedUsers configuration section.
- Certificate is modified by the server in two ways:
    - KeyId is overwritten to be the value stored in the server's
      configuration file. This means that the server administrator has
      control over what value appears in the KeyId field since this is
      used for logging in many places outside of ssh-cert-authority.
    - The Serial field is overwritten to be the next serial number. When
      OpenSSH supports it this may be used for certificate revocation.
      OpenSSH does not support revocation today. To combat this it is
      recommended that certificates not be generated with long
      lifetimes.
- Certificate is stored, verbatim, in memory.
- A random request id is generated and returned the caller.
- Signer downloads that exact certificate from the server using the
  request id.
- Signer verifies the signature is valid
- Signer, a user that is presumably human, decides to sign the certificate
- The Nonce value in the certificate is made anew and the certificate is
  signed by the signer in the exact same way that the requester signs.
- The server verifies that the certificate has a valid signature from a
  user in the AuthorizedSigners configuration section.
- Server verifies that all fields in the signing command exactly match
  those of the original request (except signature, nonce, and signing
  key)
- If the requisite number of signatures has been received the
  certificate request that was stored in memory (with updated KeyId and
  Serial fields) as part of the request is pushed over to the local
  ssh-agent and asked to be signed by the cert authority's private key.
- Any one with the request id may download the signed certificate.

The ssh-cert-authority tools and daemon never ever see or transit
secrets. We deal only in public keys and certificates none of which need
to be treated as secret. This limits the scope of the threats we protect
against to be mostly around "don't sign a cert for someone that isn't
supposed to request one" and "don't allow someone unauthorized to sign a
cert."

