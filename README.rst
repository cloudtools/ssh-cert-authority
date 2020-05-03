==================
ssh-cert-authority
==================

Introduction
============

A democratic SSH certificate authority.

Operators of ssh-cert-authority want to use SSH certificates to provide
fine-grained access control to servers they operate, enforce the 2-person rule,
keep their certificate signing key a secret and not need to be required to get
involved to actually sign certificates. A tall order.

The idea here is that a user wishing to access a server runs
``ssh-cert-authority request`` and specifies a few parameters for the cert
request like how long he/she wants it to be valid for. This is POSTed to
the ``ssh-cert-authority runserver`` daemon which validates that the
certificate request was signed by a valid user (configured on the daemon
side) before storing a little state and returning a certificate id to
the requester.

The requester then convinces one or more of his or her authorized
friends (which users are authorized and the number required is
configured on the daemon side) to run the ``ssh-cert-authority sign``
command specifying the request id. The signer is allowed to see the
parameters of the certificate before deciding whether or not to actually
sign the cert request. The signed certificate is again POSTed back to
the server where the signature is validated.

Note that a requester may not sign their own request. If a +1 is
received for a request by the same key as the one in the request then
the signing request is rejected.

Once enough valid signatures are received the cert request is
automatically signed using the signing key for the cert authority and
made available for download by the requester using the request id.

None of the code here ever sees or even attempts to look at secrets. All
signing operations are performed by ``ssh-agent`` running on respective
local machines. In order to bootstrap the signing daemon you must
``ssh-add`` the signing key. In order to request a cert or sign someone's
cert request the user must have the key used for signing loaded up in
``ssh-agent``. Secrets are really hard to keep, we'll leave them in the
memory space of ``ssh-agent``.

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
    - Put everyone's public key into an ``authorized_keys`` file (perhaps
      baked into an AMI, perhaps via cloudinit)

In security conscience environments organizations may have built a tool
that automates the process of adding and removing public keys from an
``authorized_keys`` file.

None of these options are great. The first two options do not meet the
security requirements of the author's employer. Sharing secrets is
simply unacceptable and it means that an ex-employee now has access to
systems that he or she shouldn't have access to until the key can be
rotated out of use.

Managing a large ``authorized_keys`` file is a problem because it isn't
limited to the exact set of people that require access to nodes right
now.

As part of our ISO 27001 certification we are additionally required to:

    - Automatically revoke access to systems when engineers no longer
      need access to them.
    - Audit who accessed which host when and what they did

SSH certificates solve these problems and more.

An OpenSSH certificate is able to encode a set of permissions of the
form (see also the ``CERTIFICATES`` section of ``ssh-keygen(1)``):

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

That command outputs two files::

    my_ssh_cert_authority: The encrypted private key for your new authority
    my_ssh_cert_authority.pub: The public key for your new authority.

Be sure you choose a passphrase when prompted so that the secret is
stored encrypted. Other options to ``ssh-keygen`` are permitted including
both key type and key parameters. For example, you might choose to use
ECDSA keys instead of RSA.

Grab the fingerprint of your new CA::

    $ ssh-keygen -l -f my_ssh_cert_authority
    2048 2b:a1:16:84:79:0a:2e:38:84:6f:32:96:ab:d4:af:5d my_ssh_cert_authority.pub (RSA)

Now that you have a certificate authority you'll need to tell the hosts
in your environment to trust this authority. This is done very similar
to user SSH keys by setting up the ``authorized_keys`` on your hosts (the
expectation is that you're setting this up at launch time via cloudinit
or perhaps baking the change into an OS image or other form of snapshot).

You have a choice of putting this ``authorized_keys`` file into
``$HOME/.ssh/authorized_keys`` or the change can be made system wide. For
system wide configuration see ``sshd_config(5)`` and the
``TrustedUserCAKeys`` option.

If you are modifying the user's ``authorized_keys`` file simply add a new
line to ``authorized_keys`` of the form::

    cert-authority <paste the single line from my_ssh_cert_authority.pub>

A valid line might look like this for an RSA key::

    cert-authority ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAYQC6Shl5kUuTGqkSc8D2vP2kls2GoB/eGlgIb0BnM/zsIsbw5cWsPournZN2IwnwMhCFLT/56CzT9ZzVfn26hxn86KMpg76NcfP5Gnd66dsXHhiMXnBeS9r6KPQeqzVInwE=

At this point your host has been configured to accept a certificate
signed by your authority's private key. Let's generate a certificate for
ourselves that permits us to login as the user ubuntu and that is valid
for the next hour (This assumes that our personal public SSH key is
stored at ``~/.ssh/id_rsa.pub)`` ::

    ssh-keygen -V +1h -s my_ssh_cert_authority -I bvanzant -n ubuntu ~/.ssh/id_rsa.pub

The output of that command is the file ``~/.ssh/id_rsa-cert.pub``. If you
open it it's just a base64 encoded blob. However, we can ask ``ssh-keygen``
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

At this point if you look in ``/var/log/auth.log`` (Ubuntu) (``/var/log/secure``
on Red Hat based systems) you'll see that the user ubuntu logged in to this
machine. This isn't very useful data. If you change the sshd_config on your 
servers to include ``LogLevel VERBOSE`` you'll see that the certificate key id
is also logged when a user logs in via certificate. This allows you to map
that user ``bvanzant`` logged into the host using username ubuntu. This will
make your auditors happy.

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
    - encrypt-key
    - generate-config

As you might have guessed by now this means that a server needs to be
running and serving the ssh-cert-authority service. Users that require
SSH certificates will need to be able to access this service in order to
request, sign and get certificates.

This tool was built with the idea that organizations have more than one
environment with perhaps different requirements for obtaining and using
certificates. For example, there might be a test environment, a staging
environment and a production environment. Throughout the examples we
assume a single environment named "production."

In all cases this tool relies heavily on ``ssh-agent``. It is entirely
feasible that ``ssh-agent`` could be replaced by any other process capable
of signing a blob of data with a specified key including an HSM.

Many of the configuration files use SSH key fingerprints. To get a key's
fingerprint you may run ``ssh-keygen -l -f <filename>`` or, if the key is
already stored in your ``ssh-agent`` you can ``ssh-agent -l``.

Setting up the daemon
---------------------

ssh-cert-authority uses json for its configuration files. By default the
daemon expects to find its configuration information in
``$HOME/.ssh_ca/sign_certd_config.json`` (you can change this with a
command line argument). A valid config file for our production
environment might be::
    {
      "production": {
            "NumberSignersRequired": 1,
            "MaxCertLifetime": 86400,
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
            MaxCertLifetime
            SigningKeyFingerprint
            PrivateKeyFile
            KmsRegion
            AuthorizedSigners {
                <key fingerprint>: <key identity>
            }
            AuthorizedUsers {
                <key fingerprint>: <key identity>
            }
    }

- ``NumberSignersRequired``: The number of people that must sign a request
  before the request is considered complete and signed by the authority.
  If this field is < 0 valid certificate requests will be automatically
  signed at request time. It is highly recommended that if auto signing
  is enabled a ``MaxCertLifetime`` be specified.
- ``MaxCertLifetime``: The maximum duration certificate, measured from Now()
  in seconds, that is permitted. The default is 0, meaning unlimited. A
  value of 86400 would mean that the server will reject requests for
  certificates that are valid for more than 1 day.
- ``SigningKeyFingerprint``: The fingerprint of the key that will be used to
  sign complete requests. This should be the fingerprint of your CA. When using
  this option you must, somehow, load the private key into the agent such that
  the daemon can use it.
- ``PrivateKeyFile``: A path to a private key file or a Google KMS key url.

  If you have specified a file system path the key may be unencrypted or have
  previousl been encrypted using Amazon's KMS. If the key was encrypted using
  KMS simply name it with a ".kms" extension and ssh-cert-authority will
  attempt to decrypt the key on startup. See the section on Encrypting a CA Key
  for help in using KMS to encrypt the key.

  If you specified a Google KMS key it should be of the form:
  ``gcpkms:///projects/<project-name>/locations/<region|global>/keyRings/<keyring
  name>/cryptoKeys/<keyname>/cryptoKeyVersions/<version-number>``

- ``KmsRegion``: If sign_certd encounters a privatekey file with an
  extension of ".kms" it will attempt to decrypt it using KMS in the
  same region that the software is running in. It determines this using
  the local instance's metadata server. If you're not running
  ssh-cert-authority within AWS or if the key is in a different region
  you'll need to specify the region here as a string, e.g. us-west-2.
- ``AuthorizedSigners``: A hash keyed by key fingerprints and values of key
  ids. I recommend this be set to a username. It will appear in the
  resultant SSH certificate in the KeyId field as well in
  ssh-cert-authority log files. The ``AuthorizedSigners`` field is used to
  indicate which users are allowed to sign requests.
- ``AuthorizedUsers``: Same as ``AuthorizedSigners`` except that these are
  fingerprints of people allowed to submit requests.
- ``CriticalOptions``: A hash of critical options to be added to all
  certificate requests. By specifying these in your configuration file
  all cert requests to this environment will have these options embedded
  in them. You can use this option, for example, to restrict the IP
  addresses that are allowed to use a certificate or to force a user
  to only be able to run a single command. Those are the only two
  options supported by sshd right now. This document describes them in
  the section ``Critical options``:
  http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?rev=HEAD

The same users and fingerprints may appear in both ``AuthorizedSigners`` and
``AuthorizedUsers``.

You're now ready to start the daemon. I recommend putting this under the
control of some sort of process monitor like upstart or supervisor or
whatever suits your fancy.::

    ssh-cert-authority runserver

Log messages go to stdout. When the server starts it prints its config
file as well as the location of the ``$SSH_AUTH_SOCK`` that it found

If you are running this from within a process monitor getting a
functioning ``ssh-agent`` may not be intuitive. I run it like this::

    ssh-agent ssh-cert-authority runserver

This means that a new ``ssh-agent`` is used exclusively for the server. And
that means that every time the service starts (or restarts) you must
manually add your signing keys to the agent via ``ssh-add``. To help  with
this the server prints the socket it's using::

    2015/04/12 16:05:05 Using SSH agent at /private/tmp/com.apple.launchd.MzybvK44OP/Listeners

You can take that value and add in your keys like so::

    SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.MzybvK44OP/Listeners ssh-add path-to-ca-key

Once the server is up and running it is bound to 0.0.0.0 on port 8080.

Running behind a reverse proxy (e.g. nginx)
-------------------------------------------

If you're running behind a reverse proxy, which this project recommends,
you will want to set one additional command line argument,
``reverse-proxy``. You can instead set the environment variable
SSH_CERT_AUTHORITY_PROXY=true if that is more your style. Setting this
flag to true instructs the daemon to trust the X-Forwarded-For header
that nginx will set and to use that IP address in log messages. Know
that you must not set this value to true if you are not running behind a
proxy as this allows a malicious user to control the value of the IP
address that is put into your log files.

Command Line Flags
------------------

- ``config-file``: The path to a config.json file. Used to override the
  default of $HOME/.ssh_ca/sign_certd_config.json
- ``listen-address``: Controls the bind address of the daemon. By
  default we bind to localhost which means you will not be able to
  connect to the daemon from hosts other than this one without using a
  reverse proxy (e.g. nginx) in front of this daemon. A reverse proxy is
  the recommended method for running this service in production.
- ``reverse-proxy``: When specified the daemon will trust the
  X-Forwarded-For header as added to requests by your reverse proxy.
  This flag must not be set when you are not using a reverse proxy as it
  permits a malicious user to control the IP address that is written to
  log files.

Storing Your CA Signing Key in Google Cloud
===========================================
Google Cloud KMS supports signing operations and ssh-cert-authority can use
these keys to sign the SSH certificates it issues. If you do this you'll likely
want to have your ssh-cert-authority running on an instance in GCP and
configured with a service account that can use the key.

ssh-cert-authority has been tested with ecdsa keys from prime256v1 both
software and hardware backed. Other key kinds and curves might work.

This example assumes you have a functioning gcloud already.

Setting up keys::

  # First create a keyring to store keys
  gcloud kms keyrings create ssh-cert-authority-demo --location us-central1

  # Create keys on that keyring for dev and prod
  gcloud alpha kms keys create --purpose asymmetric-signing --keyring ssh-cert-authority-demo \
    --location us-central1 --default-algorithm ec-sign-p256-sha256 dev
  gcloud alpha kms keys create --purpose asymmetric-signing --keyring ssh-cert-authority-demo \
    --location us-central1 --default-algorithm ec-sign-p256-sha256 prod

  # Create a service account for the system
  gcloud iam service-accounts create ssh-cert-authority-demo

  # If you're using a GCP instance you should launch your instance and specify
  # that service account as the account for the instance. If you're running
  # this on a local machine or an AWS instance or something you will need to
  # explicitly get the service account key
  gcloud iam service-accounts keys create ssh-cert-authority-demo-serviceaccount.json
      --iam-account ssh-cert-authority-demo@YOUR_GOOGLE_PROJECT_ID.iam.gserviceaccount.com
  
  # You need to set that key file in an environment variable now:
  export GOOGLE_APPLICATION_CREDENTIALS=/path/to/ssh-cert-authority-demo-serviceaccount.json

  # Give that service account permission to use our newly created keys:
  gcloud kms keys add-iam-policy-binding  ssh-cert-authority-dev-hsm --location us-central1 \
      --keyring ssh-cert-authority-demo \
      --member serviceAccount:ssh-cert-authority-demo@YOUR_GOOGLE_PROJECT_ID.iam.gserviceaccount.com \
      --role roles/cloudkms.signerVerifier

  # Get the path to the keys we created:
  gcloud kms keys list --location us-central1 --keyring ssh-cert-authority-demo

  # That will print out the two keys we created earlier including the name of
  # the key. The name of the key is a big path that begins with projects/. We
  # need to copy this entire path into our sign_certd_config.json as the
  # PrivateKeyFile for the environment. A minimal example showing only dev:
  
  {
    "dev": {
        "NumberSignersRequired": -1,
        "MaxCertLifetime": 86400,
        "PrivateKeyFile": "gcpkms:///projects/YOUR_GOOGLE_PROJECT_ID/locations/us-central1/keyRings/ssh-cert-authority-demo/cryptoKeys/dev/cryptoKeyVersions/1",
        "AuthorizedSigners": {
            "a7:64:9e:35:5d:ae:c6:bd:79:f1:e3:c8:92:0b:9a:51": "bvz"
        },
        "AuthorizedUsers": {
            "a7:64:9e:35:5d:ae:c6:bd:79:f1:e3:c8:92:0b:9a:51": "bvz"
        }
    }
  }


Encrypting a CA Key Using Amazon's KMS
======================================

Amazon's KMS (Key Management Service) provides an encryption key
management service that can be used to encrypt small chunks of arbitrary
data (including other keys). This project supports using KMS to keep the
CA key secure.

The recommended deployment is to launch ssh-cert-authority onto an EC2
instance that has an EC2 instance profile attached to it that allows it
to use KMS to decrypt the CA key. A sample cloudformation stack is
forthcoming to do all of this on your behalf.

Create Instance Profile
-----------------------

In the mean time you can set things up by hand. A sample EC2 instance
profile access policy::

    {
        "Statement": [
            {
                "Resource": [
                    "*"
                ],
                "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt",
                    "kms:GenerateDataKey",
                    "kms:DescribeKey"
                ],
                "Effect": "Allow"
            }
        ],
        "Version": "2012-10-17"
    }

Create KMS Key
--------------

Create a KMS key in the AWS IAM console. When specifying key usage allow the
instance profile you created earlier to use the key. The key you create
will have an id associated with it, it looks something like this::

    arn:aws:kms:us-west-2:123412341234:key/debae348-3666-4cc7-9d25-41e33edb2909

Save that for the next step.

Launch Instance
---------------

Now launch an instance and use the EC2 instance profile. A t2 class instance is
likely sufficient. Copy over the latest ssh-cert-authority binary (you
can also use the container) and generate a new key for the CA using
ssh-cert-authority. The nice thing here is that the key is never written
anywhere unencrypted. It is generated within ssh-cert-authority,
encrypted via KMS and then written to disk in encrypted form. ::

    environment_name=production
    ssh-cert-authority encrypt-key --generate-rsa \
        --key-id arn:aws:kms:us-west-2:881577346222:key/d1401480-8220-4bb7-a1de-d03dfda44a13 \
        --output ca-key-${environment}.kms

The output of this is two files: ``ca-key-production.kms`` and
``ca-key-production.kms.pub``. The kms file should be referenced in the ssh
cert authority config file, as documented elsewhere in this file, and
the .pub file will be used within authorized_keys on servers you wish to
SSH to.

``--generate-rsa`` will generate a 4096 bit RSA key. ``--generate-ecdsa`` will
generate a key from nist's p384 curve.

Requesting Certificates
=======================

See USAGE.rst in this directory.

Signing Requests
================

See USAGE.rst in this directory.

All in one basic happy test case::

    go build && reqId=$(./ssh-cert-authority request --reason testing --environment test --quiet) && \
    ./ssh-cert-authority sign --environment test --cert-request-id $reqId && \
    ./ssh-cert-authority get --add-key=false --environment test $reqId`
