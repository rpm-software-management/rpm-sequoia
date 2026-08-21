FROM quay.io/fedora/fedora:latest
MAINTAINER jjelen@redhat.com

RUN dnf install -y \
    rust \
    cargo \
    clang-devel \
    git \
    pkg-config \
    openssl-devel
