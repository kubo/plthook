#!/bin/bash

case "$1" in
  x86_64)
    ARCH=x86-64-core-i7
    LIBC=uclibc
    TOOLCHAIN_VER=stable-2018.11-1
    TARGET_PLATFORM=x86_64-buildroot-linux-uclibc
    ;;
  i686)
    ARCH=x86-core2
    LIBC=uclibc
    TOOLCHAIN_VER=stable-2018.11-1
    TARGET_PLATFORM=i686-buildroot-linux-uclibc
    ;;
esac

set -e

THIS_COMMAND=$0

run_make() {
  BASE_NAME=$ARCH--$LIBC--$TOOLCHAIN_VER
  export SYSROOT=$BASE_NAME/$TARGET_PLATFORM/sysroot
  if test -f $BASE_NAME.tar.bz2; then
    echo Found $BASE_NAME.tar.bz2
  else
    echo Download $BASE_NAME.tar.bz2
    wget https://toolchains.bootlin.com/downloads/releases/toolchains/$ARCH/tarballs/$BASE_NAME.tar.bz2
  fi
  if test -d $BASE_NAME; then
    echo Found $BASE_NAME
  else
    echo Extract $BASE_NAME.tar.bz2
    tar xfj $BASE_NAME.tar.bz2
  fi
  if test -h $SYSROOT/proc/self; then
    echo Found $SYSROOT/proc/self
  else
    echo Mount $SYSROOT/proc
    sudo mount -t proc none $SYSROOT/proc
  fi
  export RUN_AS_KICK_CMD=1
  export PATH="$BASE_NAME/bin:$PATH"
  make relro_pie_tests TARGET_PLATFORM=$TARGET_PLATFORM KICK_CMD=$THIS_COMMAND
}

kick_cmd() {
  cp testprog $SYSROOT/usr/bin
  cp libtest.so $SYSROOT/usr/lib
  cd $SYSROOT
  shift
  sudo chroot . ./usr/bin/testprog "$@"
}

if test "$RUN_AS_KICK_CMD"; then
  kick_cmd "$@"
else
  run_make "$@"
fi
