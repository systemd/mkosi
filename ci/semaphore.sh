#!/bin/bash

set -ex

# Build an image
sudo add-apt-repository --yes ppa:deadsnakes/ppa
sudo add-apt-repository --yes ppa:ubuntu-iremonger/e2fsprogs-xenial
sudo apt --yes update
sudo apt --yes install python3.6 python3-pip debootstrap systemd-container squashfs-tools e2fsprogs xfsprogs

testimg()
{
        img="$1"
        sudo python3.6 ./mkosi --no-chown --default ./mkosi.files/mkosi."$img"
        if test -f mkosi.output/"$img".raw ; then
                sudo rm -f mkosi.output/"$img".raw
        elif test -d mkosi.output/"$img" ; then
                sudo rm -rf mkosi.output/"$img"
        elif test -f mkosi.output/"$img".tar.xz ; then
                sudo rm -f mkosi.output/"$img".tar.xz
        else
                echo "Couldn't find generated image." >&2
                exit 1
        fi
}

# Only test ubuntu images for now, as semaphore is based on Ubuntu
for i in ./mkosi.files/mkosi.ubuntu*
do
        imgname="$(basename "$i" | cut -d. -f 2-)"
        testimg "$imgname"
done

# Run unit tests
sudo python3.6 -m pip install pytest
sudo python3.6 -m pytest

# Run mypy check
sudo python3.6 -m pip install 'mypy==0.770'
sudo python3.6 -m mypy mkosi
