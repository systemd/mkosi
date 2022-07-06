#!/bin/bash

set -e

cd $(dirname $0)
[ -d rhino-convert ] && rm -r rhino-convert
[ -d convert ] && rm -r convert

#TODO: Uncomment when the below PR is merged:
#
#   https://github.com/rollingrhinoremix/rhino-convert/pull/2
#
#git clone https://github.com/rollingrhinoremix/rhino-convert.git

#TODO: Remove these lines when the above PR is merged
git clone https://github.com/mcassaniti/rhino-convert.git
cd rhino-convert
git checkout origin/convert-vs-creation-directories-v1 > /dev/null 2>&1
cd ..
# END lines to remove

# The update process will prompt for confirmation without this option
echo 'APT::Get::Assume-Yes "yes";' > /etc/apt/apt.conf.d/00-apt-assume-yes

# Silences sudo name resolution errors
echo "127.0.0.2 $(hostname)" > /etc/hosts

# Convert the OS from Ubuntu to Rhino
chmod +x rhino-convert/convert.sh
rhino-convert/convert.sh

# Update the mirror used when it is not the default
if [ "$MIRROR" != "http://archive.ubuntu.com/ubuntu" ] ; then
    # Taken from:
    # https://github.com/rollingrhinoremix/assets/blob/0c5983475a6bc29c51d62135021b4ac51fd2470c/.sources.sh

    cat > /etc/apt/sources.list << EOF
deb $MIRROR devel main restricted
deb $MIRROR devel-updates main restricted
deb $MIRROR devel universe
deb $MIRROR devel-updates universe
deb $MIRROR devel multiverse
deb $MIRROR devel-updates multiverse
deb $MIRROR devel-backports main restricted universe multiverse
deb $MIRROR devel-security main restricted
deb $MIRROR devel-security restricted
deb $MIRROR devel-security multiverse

EOF

fi

# Update the OS
source .bash_aliases
shopt -s expand_aliases
rhino-init
rhino-update

rm /etc/hosts
rm /etc/apt/apt.conf.d/00-apt-assume-yes
rm -rf rhino-convert

# Remove if rhino-update ever supports caching. See:
#   https://github.com/rollingrhinoremix/rhino-update/issues/64
rm -rf $HOME/.rhino
