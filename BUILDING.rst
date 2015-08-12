===============
Building SSH CA
===============

We use docker to both build and run ssh-cert-authority. Images are
available at hub.docker.com. To use these images simply
`docker pull cloudtools/ssh-cert-authority`. If you want to build your
own images, these instructions should help.

We have two Dockerfiles. One is for building an environment to build
ssh-cert-authority. This bootstraps a linux machine to the point that it
can compile a go binary for linux and OS X. The next is for building a
container that can run the ssh-cert-authority web service.

Though keep in mind that you probably don't need to do any of this
unless you're hacking on the software or have stringent security
requirements that state you build your own copy of this.

Building with Docker
====================

As an alternative to installing and maintaining a go build environment on your
machine, you can utilize Docker to run the build process in isolation. To do
so, you first need to build the container defined by the Dockerfile included
in this repository.::

    docker build -f Dockerfile-buildenv -t cloudtools/ssh-cert-authority-buildenv .

Once this process has completed, you can run an instance of the container
image with a bind mount to this project's directory and the build script
specified as the command to run.::

    docker run \
        -v `pwd`:/build/ssh-cert-authority/go/src/github.com/cloudtools/ssh-cert-authority \
        -t cloudtools/ssh-cert-authority-buildenv \
        bash build.sh

This will generate two files in the project directory; a gzipped binary for
64bit linux and another for 64bit OSX. You can use this binary directly to run
the program by gunzipping it and `chmod +x` ing it

Creating a Runtime container
============================

Once you've built the software and have the linux .gz file in the
current directory you can also choose to build a container that runs the
cert authority service. This is as simple as ::

    docker build -t cloudtools/ssh-cert-authority .

That container is setup to run ssh-cert-authority underneath ssh-agent
(as recommended in other documentation in this repository). This creates
an interesting challenge. When you start the container using something
like this::

    docker run --name ssh-cert-authority -v my_ca_encrypted_secret_key:/etc/ssh/my_ca_encrypted_secret_key -v sign_certd_config.json:/etc/ssh-cert-authority.json:ro cloudtools/ssh-cert-authority --config-file /etc/ssh-cert-authority.json
    2015/08/12 15:38:12 Server running version 1.0.0
    2015/08/12 15:38:12 Server started with config ...
    2015/08/12 15:38:12 Using SSH agent at /tmp/ssh-YMAx2oKHLPrU/agent.1

You now need to load your CA key into that agent. If you trust your
environment you can use::

    # Add your key to the agent, it will prompt for passphrase
    docker exec -it ssh-cert-authority bash -c ssh-add bash -c "export SSH_AUTH_SOCK=/tmp/ssh-MAx2oKHLPrU/agent.1; ssh-add /etc/ssh/my_ca_encrypted_secret_key"
    # Show the identities in the agent.
    docker exec -it ssh-cert-authority bash -c ssh-add bash -c "export SSH_AUTH_SOCK=/tmp/ssh-MAx2oKHLPrU/agent.1; ssh-add -l"

The problem is in how docker exec works. If you're on the host that's
running this container the exec is forwarding your keystrokes (the tty
it sets up) over local sockets and depending on your security posture
this may or may not be ok depending on your security posture. If its
over a network and you've setup docker with TLS this, again, may or may
not be acceptable to you.

The maintainers of this project are interested in feedback in this area.
Should we spin up sshd inside this container too so that you can
more-securely get inside the container and run ssh-add?

Should ssh-agent be decoupled from this container (running ssh-agent on
the host makes it ~difficult to pass the agent socket into the running
container, for better or worse)?

Feedback is welcome here.
