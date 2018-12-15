#!/bin/bash

set -ex

sudo add-apt-repository --yes ppa:jonathonf/python-3.6
sudo apt --yes update
sudo apt --yes install python3.6 debootstrap systemd-container squashfs-tools

sudo python3.6 ./mkosi --default ./mkosi.files/mkosi.ubuntu

test -f ubuntu.raw
