FROM docker.io/library/debian:12
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends ca-certificates openssl python3 openjdk-17-jre-headless strace >/dev/null && useradd -m bruser && rm -rf /var/lib/apt/lists/*
