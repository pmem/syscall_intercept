#!/bin/sh -e

export LC_ALL=C

git archive HEAD | gzip > syscall-intercept_0.1.orig.tar.gz
rm -rf build-deb
mkdir build-deb
cd build-deb
tar xf ../syscall-intercept_0.1.orig.tar.gz
debuild -us -uc
