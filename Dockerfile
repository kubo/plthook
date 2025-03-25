# Dockerfile for QEMU testing
FROM ubuntu:latest

RUN apt update \
    && apt install -y \
        make \
        qemu-user \
        gcc-arm-linux-gnueabi \
        gcc-arm-linux-gnueabihf \
        gcc-aarch64-linux-gnu \
        gcc-powerpc-linux-gnu \
        gcc-powerpc64le-linux-gnu \
        gcc-riscv64-linux-gnu \
        libc6-dev-armhf-cross \
        libc6-dev-ppc64el-cross \
        libc6-dev-powerpc-cross \
        libc6-dev-armel-cross \
        libc6-dev-arm64-cross

WORKDIR /plthook

COPY . .

WORKDIR /plthook/test

ENV OPT_CFLAGS="-O3"

RUN echo "Running tests" \
    && make relro_pie_tests TARGET_PLATFORM=aarch64-linux-gnu \
    && make relro_pie_tests TARGET_PLATFORM=arm-linux-gnueabi \
    && make relro_pie_tests TARGET_PLATFORM=arm-linux-gnueabihf \
    && make relro_pie_tests TARGET_PLATFORM=powerpc-linux-gnu QEMU_ARCH=ppc \
    && make relro_pie_tests TARGET_PLATFORM=powerpc64le-linux-gnu QEMU_ARCH=ppc64le \
    && make relro_pie_tests TARGET_PLATFORM=riscv64-linux-gnu QEMU_ARCH=riscv64
