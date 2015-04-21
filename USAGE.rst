============
Using SSH CA
============

Requesting a signed certificate
===============================

Super basic
-----------
::

  ssh-cert-authority request --environment stage --reason "Do important maintenance work"


Configuration
-------------

ssh_ca assumes that you have several environments each with different
certificate authorities and that they are configured differently. For
example you might have separate environments for staging and production
each with different CAs. This tool supports that.

Here's a sample requester config file. The default location for this is
$HOME/.ssh_ca/requester_config.json ::
    {
        "stage": {
            "PublicKeyPath": "/Users/bvanzant/.ssh/bvanzant-stage.pub",
            "SignerUrl": "http://ssh-ca:8080/"
        },
        "prod": {
            "PublicKeyPath": "/Users/bvanzant/.ssh/bvanzant-prod.pub",
            "SignerUrl": "http://ssh-ca:8080/"
        }
    }

The contents should be reasonably self explanatory. Here we have a json
blob containing a stage and prod environment. The user has chosen to use
different SSH keys for production and staging, however, this is not
required. The SignerUrl is the location of the ssh_ca daemon.

Making a request
----------------

Once configured requesting a certificate is as simple as::

  ssh-cert-authority request --environment stage --reason "Do important maintenance work"

This will print out a certificate request id like so::

  Cert request id: HWK6CTFJDPTXRAXD7S6NZHO3

Hand this id off to someone that can sign your cert.

If instead you got an error like
`ssh-add the private half of the key you want to use.` then go do that.
Under the hood the `request_cert` command is going to use your SSH
private key to sign your certificate request. This is how the signing
daemon knows that you are the person that actually requested the cert
(you have control of the private key and your private key is actually
private, right?). This is typically as simple as `ssh-add ~/.ssh/id_rsa`
but if you've got lots of keys or per-environment config you'll need to
adjust and ensure you both add the right key and that your
requester_config.json is specifying the right public key.

Signing certificates
====================

Super basic
-----------
::
    ssh-cert-authority sign --environment stage HWK6CTFJDPTXRAXD7S6NZHO3

Configuration
-------------

A sample signer config. By default this is in
$HOME/.ssh_ca/signer_config.json ::

    {
        "stage": {
            "KeyFingerprint": "66:b5:be:e5:7e:09:3f:98:97:36:9b:64:ec:ea:3a:fe",
            "SignerUrl": "http://ssh-ca:8080/"
        },
        "prod": {
            "KeyFingerprint": "66:b5:be:e5:7e:09:3f:98:97:36:9b:64:ec:ea:3a:fe",
            "SignerUrl": "http://ssh-ca:8080/"
        }
    }

In this case the configuration is slightly different from requesting
because we're dealing with fingerprints instead of paths. You can easily
get the fingerprint of the private key you want to sign with by doing
`ssh-keygen -l -f ~/.ssh/id_rsa` or inspecting the output of `ssh-add
-l` (the ssh-add -l output is only relevant if your private key is
loaded in your agent).

Signing a request
-----------------

A word of caution: Treat signing requests very seriously. This is easily
the weak point in the entire system. Inspect requests intently and look
for violations of your policy on shell access to machines.

The signing portion of a request begins when someone sends you a request
id. You then sign it by::
    $ ssh-cert-authority sign --environment stage HWK6CTFJDPTXRAXD7S6NZHO3
    Certificate data:
      Serial: 2
      Key id: bvanzant+stage@brkt.com
      Principals: [ec2-user ubuntu]
      Options:
      Permissions:
          ca-environment: stage
          ca-reason: testing build #11
          permit-agent-forwarding:
          permit-port-forwarding:
          permit-pty:
      Valid for public key: 1c:fd:36:27:db:48:3f:ad:e2:fe:55:45:67:b1:47:99
      Valid from 2015-03-31 08:21:39 -0700 PDT - 2015-03-31 10:21:39 -0700 PDT
    Type 'yes' if you'd like to sign this cert request

Inspect every field and compare it to what you know about who is requesting
this certificate and why. I'll provide a brief explanation of these here
but for more information checkout the CERTIFICATES section of
ssh-keygen(1)

    - Does the key id match with who requested the cert?
    - Principals specifies the list of usernames that a requester can
      use to login to systems as. In our example here the user is
      allowed to use ec2-user and ubuntu.
    - Permissions is a list of ssh permissions that this cert grants. In
      particular permit-pty will allow the user to open up a shell. Here
      we also see permit-agent-forwarding which allows the user to
      forward along their ssh-agent connection (generally useful) and
      permit-port-forwarding which allows the user of this cert to
      forward ports along connections.

Also inspect the validity period. What is normal for your organization?
In general the less time a certificate is valid for the less likely it
is to be abused. sign_cert will print out the expiry time of a
certificate in red if the value is more than 48 hours in the future.

If you, as a signer, are happy with the certificate request you can type
`yes` and the certificate will be, effectively, +1'ed by you. Any other
input is ignored and sign_cert exits.

In order for sign_cert to run your SSH key must be loaded in ssh-agent
(via ssh-add). Otherwise sign_cert will exit with an error::

  ssh-add the private half of the key you want to use.

Downloading a signed certificate
================================

Super basic
-----------
::
  ssh-cert-authority get --environment stage HWK6CTFJDPTXRAXD7S6NZHO3

Configuration
-------------

The get command uses the requester_config.json file described under
requesting a certificate.

