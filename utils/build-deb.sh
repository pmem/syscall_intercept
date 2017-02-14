#!/bin/sh -e

export LC_ALL=C

rm -rf build-deb
mkdir -p build-deb/syscall_intercept
git archive HEAD | gzip > build-deb/syscall-intercept_0.1.orig.tar.gz
cd build-deb/syscall_intercept
tar xf ../syscall-intercept_0.1.orig.tar.gz
debuild -us -uc
