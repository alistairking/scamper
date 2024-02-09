#!/bin/sh
#
# set the version string in configure.ac and scamper/scamper.h

set -e

if [ "$#" -ne 1 ]; then
   echo "expecting a single command line argument (the version to set)"
   exit 1
fi

VERSION=${1?}
CHANGELOG=`mktemp`

sed -i "s/^AC_INIT(\[scamper\],\[.*\],\[mjl@luckie.org.nz\])$/AC_INIT(\[scamper\],\[${VERSION}\],\[mjl@luckie.org.nz\])/w ${CHANGELOG}" configure.ac
if [ ! -s "${CHANGELOG}" ]; then
    echo "configure.ac unchanged"
    rm "${CHANGELOG}"
    exit 1
fi
rm "${CHANGELOG}"

sed -i "s/^#define SCAMPER_VERSION .*/#define SCAMPER_VERSION \"${VERSION}\"/w ${CHANGELOG}" scamper/scamper.h
if [ ! -s "${CHANGELOG}" ]; then
    echo "scamper/scamper.h unchanged"
    rm "${CHANGELOG}"
    exit 1
fi
rm "${CHANGELOG}"

exit 0
