FROM docker.io/library/rockylinux:9
RUN dnf -y -q install openssl python3 strace findutils procps-ng >/dev/null && useradd -m bruser && dnf clean all >/dev/null
