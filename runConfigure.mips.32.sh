#!/bin/bash

export PATH=/opt/buildroot-gdb/bin:$PATH

#GCC_DIR=/opt/buildroot-gdb
#BUILD_DIR=$(shell pwd)
autoreconf;
automake;
make distclean;./configure --host=mipsel-linux --build=i686-linux ; make



