FROM docker.io/library/ubuntu:24.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends ca-certificates openssl python3 strace >/dev/null && useradd -m bruser && rm -rf /var/lib/apt/lists/*
