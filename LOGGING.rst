==========================
SSH Cert Authority Logging
==========================

One of the main goals of this project is to provide an audit trail from
the moment a user requests access to a cluster through their trials on
the cluster until finally they disconnect from the cluster for the last
time. To help administrators and auditors understand this auditability
this document describes each of the log messages that are generated.

Service Startup
===============

At system startup the daemon prints out its current configuration. The
current configuration will show exactly what was loaded into the daemon
including, for each configured environment, the authorized users and
authorized signers as well as the policy.

Example startup messages, formatted for improved clarity.

Here is our first log message indicating the version of software we're
running. In this case its a development build.
::
	2016/04/29 14:47:53 Server running version dev

Here we log which ssh-agent we're using. ssh-cert-authority does not
sign certificates itself, it relies on a "security module" to do the
signing and ssh-agent is that module providing separation between the
user-facing service and the actual secrets.

::
	2016/04/29 14:47:53 Using SSH agent at /private/tmp/com.apple.launchd.GZGjDj9R8K/Listeners

And here is the config dump. From this we can see that the daemon was
configured to accept cert requests from bvz & dennis and that bvz is the
only configured signer. When a cert gets the correct number of signers,
1, the cert will be signed using the CA with fingerprint "00:f3:ce:..."::

    map[string]ssh_ca_util.SignerdConfig{
        "test":
            ssh_ca_util.SignerdConfig{
                SigningKeyFingerprint: "00:f3:ce:02:e7:63:77:dc:65:be:c5:24:ee:1d:63:c0",
                AuthorizedSigners: map[string]string{
                    "66:b5:be:e5:7e:09:3f:98:97:36:9b:64:ec:ea:3a:fe":"bvz"
                },
                AuthorizedUsers: map[string]string{
                    "66:b5:be:e5:7e:09:3f:98:97:36:9b:64:ec:ea:3a:fe":"bvz",
                    "3e:1d:18:28:d0:56:d5:34:e5:97:89:9a:71:b0:62:3d":"dennis"
                },
                NumberSignersRequired:1,
                SlackUrl:"",
                SlackChannel:"",
                MaxCertLifetime:0,
                PrivateKeyFile:"",
                KmsRegion:""
            },
        }

Cert Request
============

When a certificate is requested from a user a log message is generated::

    2016/04/29 15:00:38 Cert request serial 1 id ONMZX7GITLGJ4BCN env test
    from 66:b5:be:e5:7e:09:3f:98:97:36:9b:64:ec:ea:3a:fe (bvz) @ [::1]:64273
    principals [ec2-user ubuntu] valid from 1461956318 to 1461963638 for
    'Investigate disk full scenario'

Let's parse this one.

``Cert request serial 1``: This certificate has been allocated serial
number 1.

``id ONMZX7GITLGJ4BCN``: This certificate was generated this random id.
This id is used by requesters and signers to sign and retrieve signed
certificates from the system. It is not embedded in the certificate.

``env test``: This certificate is for the "test" environment.

``from 66:b5:be:e5:7e:09:3f:98:97:36:9b:64:ec:ea:3a:fe (bvz)`` The request
was received for the certificate with the fingerprint listed there.
According to our configuration file this certificate is for the user
bvz.

``@ [::1]:64273`` The certificate request came in from localhost with a
source port of 64273. Typically this contains a non-localhost IP
address but that varies based on the deployment configuration (if you're
behind a reverse proxy ssh-cert-authority doesn't yet parse the
X-Forwarded-For header).

``principals [ec2-user ubuntu]`` This certificate has the principals
ec2-user and ubuntu. That maps directly to the principals option in the
certificate and allows this certificate holder to attempt to login as
either the user ``ec2-user`` or ``ubuntu``.

``valid from 1461956318 to 1461963638`` This certificate is valid between
these two unix timestamps. An easy way of decoding this timestamp is
with python::

    >>> import time
    >>> time.ctime(1461956318)
    'Fri Apr 29 14:58:38 2016'

``for 'Investigate disk full scenario'`` This is the reason that the user
specified when requesting the certificate. The encoding of these log
messages is UTF-8 and the reason field in particular is capable of
containing non-ascii characters if the user enters them. The reason is
encoded into the certificate.

Listing Pending Requests
========================

Prior to signing a request the signer must download the certificate
request. The downloading of the request is logged as shown below and the
fields are thought to be self-explanatory.

::

    2016/04/29 15:37:30 List pending requests received from [::1]:49439 for request id 'ONMZX7GITLGJ4BCN'

Signing of a Request
====================

When a cert signer signs a request they are acknowledging and explicitly
approving the request. The log message for a signature is as follows:

::

    2016/04/29 15:37:32 Signature for serial 1 id ONMZX7GITLGJ4BCN received from 66:b5:be:e5:7e:09:3f:98:97:36:9b:64:ec:ea:3a:fe (bvz) @ [::1]:49439 and determined valid

The fields in this log message map closely to those in the request. We
see the certificate serial number (covered by the signature on the
certificate) and id (decoupled from the cert). We also see the
fingerprint of the key used to sign the certificate and print (bvz) to
indicate that our configuration shows that this key is held by the user
'bvz'.

Rejecting Requests
==================

An administrator can mark a request as rejected if he or she deems it
appropriate. For example, if a user requests a certificate and does not
adequately document the request or perhaps asks for more time than the
signer is willing to sign off on it can be rejected and no other signer
can turn that over.

When rejected a pair of log messages are generated

::

    2016/04/29 15:51:16 Signature for serial 2 id C6EMOLWB3UHAQXMK received from 66:b5:be:e5:7e:09:3f:98:97:36:9b:64:ec:ea:3a:fe (bvz) @ [::1]:49459 and determined valid
    2016/04/29 15:51:16 Reject received for id C6EMOLWB3UHAQXMK

Signing of Cert by CA
=====================

When a certificate has received enough approvals to be deemed valid
(the exact number is a configuration parameter) it is signed by the
certificate authority. This generates a log message like so::

    2016/04/29 15:37:32 Received 1 signatures for ONMZX7GITLGJ4BCN, signing now.


Certificate usage
=================

After a user obtains their certificate they use it to login to a remote
machine. OpenSSH can be configured in many ways. In certain linux
distributions you may need to enable debug logging in sshd_config (debug
does not generate a logging burden) On a default CentOS 7 installation
this message is printed on login:

::

    Apr 29 17:01:20 ip-10-204-24-252 sshd[9236]: Accepted publickey for centos from 10.0.1.30 port 58964 ssh2: RSA-CERT ID bvz (serial 1) CA RSA 00:f3:ce:02:e7:63:77:dc:65:be:c5:24:ee:1d:63:c0

Parsing this message we see that the user logged in using the generic
'centos' user that comes on AWS instances. However we also have logged
the RSA-CERT ID "bvz" which came from our ssh-cert-authority
configuration file.

At this point we have tracked a user accessing a system from the time
that they requested access to when someone approved that access and
ultimately to when they accessed a specific server.

Were auditd or similar configured on the CentOS machine we could also
see what this user did once connected to this host.

