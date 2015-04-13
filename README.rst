==================
ssh-cert-authority
==================

.. image:: https://drone.io/github.com/cloudtools/ssh-cert-authority/status.png

Introduction
============

A democratic SSH certificate authority.

Operators of ssh-cert-authority want to use SSH certificates to provide
fine-grained access control to servers they operate, keep their
certificate signing key a secret and not need to be required to get
involved to actually sign certificates. A tall order.

The idea here is that a user wishing to access a server runs
`ssh-cert-authority request` and specifies a few parameters for the cert
request like how long he/she wants it to be valid for. This is POSTed to
the `ssh-cert-authority runserver` daemon which validates that the
certificate request was signed by a valid user (configured on the daemon
side) before storing a little state and returning a certificate id to
the requester.

The requester then convinces one or more of his or her authorized
friends (which users are authorized and the number required is
configured on the daemon side) to run the `ssh-cert-authority sign`
command specifying the request id. The signer is allowed to see the
parameters of the certificate before deciding whether or not to actually
sign the cert request. The signed certificate is again POSTed back to
the server where the signature is validated.

Once enough valid signatures are received the cert request is
automatically signed using the signing key for the cert authority and
made available for download by the requester using the request id.

None of the code here ever sees or even attempts to look at secrets. All
signing operations are performed by ssh-agent running on respective
local machines. In order to bootstrap the signing daemon you must
ssh-add the signing key. In order to request a cert or sign someone's
cert request the user must have the key used for signing loaded up in
ssh-agent. Secrets are really hard to keep, we'll leave them in the
memory space of ssh-agent.

Background
==========

In general the authors of this project believe that SSH access to hosts
running in production is a sometimes-necessary evil. We prefer systems
that are capable of resolving faults by themselves and that are always
fault tolerant. However, when things go wrong or when tools for
managing the system without SSH have not been built we recognize that
getting on the box is often the only option remaining to attempt to
restore service.

SSH access to hosts in dynamic datacenters like those afforded by Amazon
Web Services and Google Compute poses its own challenges. Instances may
be spun up or torn down at any time. Typically organizations do one of
two things to facilitate SSH access to instances:

    - Generate an SSH keypair and share it amongst anyone that may need
      to access production systems
    - Put everyone's public key into an authorized_keys file (perhaps
      baked into an AMI, perhaps via cloudinit)

In security conscience environments organizations may have built a tool
that automates the process of adding and removing public keys from an
authorized_keys file.

None of these options are great. The first two options do not meet the
security requirements of the author's employer. Sharing secrets is
simply unacceptable and it means that an ex-employee now has access to
systems that he or she shouldn't have access to until the key can be
rotated out of use.

Managing a large authorized_keys file is a problem because it isn't
limited to the exact set of people that require access to nodes right
now.

As part of our ISO 27001 certification we are additionally required to:

    - Automatically revoke access to systems when engineers no longer
      need access to them.
    - Audit who accessed which host when and what they did

SSH certificates solve these problems and more.

An OpenSSH certificate is able to encode a set of permissions of the
form (see also the CERTIFICATES section of ssh-keygen(1)):

    - Which user may use this certificate
    - The user id of the user
    - When access to servers may begin
    - When access to servers expires
    - Whether or not the user may open a PTY, do port forwarding or SSH
      agent forwarding.
    - Which servers may be accessed

The certificate is signed by some trusted authority (an SSH private key)
and machines within the environment are told to trust any certificate
signed by that authority. This is very, very similar to how trust works
for TLS certificates on your favorite websites.

A piece of trivia is that SSH certificates are not X.509 certs, they're
instead more along the lines of a tag-length-value encoding of a C
struct.

Using OpenSSH Certificates
==========================

This section describes using OpenSSH certificates manually, without the
ssh-cert-authority tool.

To begin using OpenSSH certificates you first must generate an ssh key
that will be kept secret and used as the certificate authority in your
environment. This can be done with a command like::

    ssh-keygen -f my_ssh_cert_authority

That command outputs two files:

    my_ssh_cert_authority: The encrypted private key for your new authority
    my_ssh_cert_authority.pub: The public key for your new authority.

Be sure you choose a passphrase when prompted so that the secret is
stored encrypted. Other options to ssh-keygen are permitted including
both key type and key parameters. For example, you might choose to use
ECDSA keys instead of RSA.

Now that you have a certificate authority you'll need to tell the hosts
in your environment to trust this authority. This is done very similar
to user SSH keys by setting up the authorized_keys on your hosts (the
expectation is that you're setting this up at launch time via cloudinit
or perhaps baking the change into an OS image or other form of snapshot).

You have a choice of putting this authorized_keys file into
`$HOME/.ssh/authorized_keys` or the change can be made system wide. For
system wide configuration see sshd_config(5) and the
AuthorizedPrincipalsFile option.

If you are modifying the user's authorized_keys file simply add a new
line to authorized_keys of the form::

    @cert-authority <paste the single line from my_ssh_cert_authority.pub>

A valid line might look like this for an RSA key::

    @cert-authority ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAYQC6Shl5kUuTGqkSc8D2vP2kls2GoB/eGlgIb0BnM/zsIsbw5cWsPournZN2IwnwMhCFLT/56CzT9ZzVfn26hxn86KMpg76NcfP5Gnd66dsXHhiMXnBeS9r6KPQeqzVInwE=

At this point your host has been configured to accept a certificate
signed by your authority's private key. Let's generate a certificate for
ourselves that permits us to login as the user ubuntu and that is valid
for the next hour (This assumes that our personal public SSH key is
stored at ~/.ssh/id_rsa.pub) ::

    ssh-keygen -V +1h -s my_ssh_cert_authority -I bvanzant -n ubuntu ~/.ssh/id_rsa.pub

The output of that command is the file `~/.ssh/id_rsa-cert.pub`. If you
open it it's just a base64 encoded blob. However, we can ask ssh-keygen
to show us the contents::

    $ ssh-keygen -L -f ~/.ssh/id_rsa-cert.pub
    /tmp/test_main_ssh-cert.pub:
        Type: ssh-rsa-cert-v01@openssh.com user certificate
        Public key: RSA-CERT f6:e3:42:5e:72:85:ce:26:e8:45:1f:79:2d:dc:0d:52
        Signing CA: RSA 4c:c6:1e:31:ed:7b:7c:33:ff:7d:51:9e:59:da:68:f5
        Key ID: "bvz-test"
        Serial: 0
        Valid: from 2015-04-13T06:48:00 to 2015-04-13T07:49:13
        Principals:
                ubuntu
        Critical Options: (none)
        Extensions:
                permit-X11-forwarding
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
                permit-user-rc

Let's use the certificate now::

    # Add the key into our ssh-agent (this will find and add the certificate as well)
    ssh-add ~/.ssh/id_rsa
    # And SSH to a host
    ssh ubuntu@<the host where you modified authorized_keys>

If the steps above were followed carefully you're now SSHed to the
remote host. Fancy?

At this point if you look in /var/log/auth.log (Ubuntu) you'll see that
the user ubuntu logged in to this machine. This isn't very useful data.
If you change the sshd_config on your servers to include `LogLevel
VERBOSE` you'll see that the certificate key id is also logged when a
user logs in via certificate. This allows you to map that user bvanzant
logged into the host using username ubuntu. This will make your auditors
happy.

You're now an SSH cert signer. The problem, however, is that you
probably don't want to be the signer. Signing certificates is not fun.
And it's really not fun at 3:00AM when someone on the team needs to
access a host for a production outage and you were not that person. That
person now has to wake you up to get a certificate signed. And you
probably don't want that. And now you perhaps are ready to appreciate
this project a bit more.

Setting up ssh-cert-authority
=============================

This section is going to build off of parts of the prior section. In
particular it assumes that you have configured an SSH authority already
and that you know how to configure servers to accept your certificates.

ssh-cert-authority is a single tool that has subcommands (the decision
to do this mostly came from trying to follow Go's preferred way of
building and distributing software). The subcommands are:

    - runserver
    - request
    - sign
    - get

As you might have guessed by now this means that a server needs to be
running and serving the ssh-cert-authority service. Users that require
SSH certificates will need to be able to access this service in order to
request, sign and get certificates.

This tool was built with the idea that organizations have more than one
environment with perhaps different requirements for obtaining and using
certificates. For example, there might be a test environment, a staging
environment and a production environment. Throughout the examples we
assume a single environment named "production."

In all cases this tool relies heavily on ssh-agent. It is entirely
feasible that ssh-agent could be replaced by any other process cable of
signing a blob of data with a specified key including an HSM.

Many of the configuration files use SSH key fingerprints. To get a key's
fingerprint you may run `ssh-keygen -l -f <filename>` or, if the key is
already stored in your ssh-agent you can `ssh-agent -l`.

Setting up the daemon
---------------------

ssh-cert-authority uses json for its configuration files. By default the
daemon expects to find its configuration information in
`$HOME/.ssh_ca/sign_certd_config.json` (you can change this with a
command line argument). A valid config file for our production
environment might be::
    {
      "production": {
            "NumberSignersRequired": 1,
            "SigningKeyFingerprint": "66:b5:be:e5:7e:09:3f:98:97:36:9b:64:ec:ea:3a:fe",
            "AuthorizedSigners": {
                "66:b5:be:e5:7e:09:3f:98:97:36:9b:64:ec:ea:3a:fe": "bvz"
            },
            "AuthorizedUsers": {
                "1c:fd:36:27:db:48:3f:ad:e2:fe:55:45:67:b1:47:99": "bvz"
            }
      }
    }

Effectively the format is::

    {
        "environment name": {
            NumberSignersRequired
            SigningKeyFingerprint
            AuthorizedSigners {
                <key fingerprint>: <key identity>
            }
            AuthorizedUsers {
                <key fingerprint>: <key identity>
            }
    }

- NumberSignersRequired: The number of people that must sign a request
  before the request is considered complete and signed by the authority.
- SigningKeyFingerprint: The fingerprint of the key that will be used to
  sign complete requests.
- AuthorizedSigners: A hash keyed by key fingerprints and values of key
  ids. I recommend this be set to a username. It will appear in the
  resultant SSH certificate in the KeyId field as well in
  ssh-cert-authority log files. The AuthorizedSigners field is used to
  indicate which users are allowed to sign requests.
- AuthorizedUsers: Same as AuthorizedSigners except that these are
  fingerprints of people allowed to submit requests.

The same users and fingerprints may appear in both AuthorizedSigners and
AuthorizedUsers.

You're now ready to start the daemon. I recommend putting this under the
control of some sort of process monitor like upstart or supervisor or
whatever suits your fancy.::

    ssh-cert-authority runserver

Log messages go to stdout. When the server starts it prints its config
file as well as the location of the $SSH_AUTH_SOCK that it found

If you are running this from within a process monitor getting a
functioning ssh-agent may not be intuitive. I run it like this::

    ssh-agent ssh-cert-authority runserver

This means that a new ssh-agent is used exclusively for the server. And
that means that every time the service starts (or restarts) you must
manually add your signing keys to the agent via ssh-add. To help  with
this the server prints the socket it's using::

    2015/04/12 16:05:05 Using SSH agent at /private/tmp/com.apple.launchd.MzybvK44OP/Listeners

You can take that value and add in your keys like so::

    SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.MzybvK44OP/Listeners ssh-add path-to-ca-key

Once the server is up and running it is bound to 0.0.0.0 on port 8080.


Requesting Certificates
=======================

See USAGE.rst in this directory.

Signing Requests
================

See USAGE.rst in this directory.
