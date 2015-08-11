===============
Building SSH CA
===============

Building with Docker
====================

As an alternative to installing and maintaining a go build environment on your
machine, you can utilize Docker to run the build process in isolation. To do
so, you first need to build the container defined by the Dockerfile included
in this repository.

    docker build -t cloudtools/ssh-cert-authority .

Once this process has completed, you can run an instance of the container
image with a bind mount to this project's directory and the build script
specified as the command to run.

    docker run \
        -v $HOME/path/to/repo:/build/ssh-cert-authority/go/src/github.com/cloudtools/ssh-cert-authority \
        -t cloudtools/ssh-cert-authority \
        bash build.sh

This will generate two files in the project directory; a gzipped binary for
64bit linux and another for 64bit OSX. You can use this binary directly to run
the program.
