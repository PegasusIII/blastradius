FROM localhost/br-ubuntu2404
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends php8.3-cli php8.3-fpm nodejs python3-certifi >/dev/null; rm -rf /var/lib/apt/lists/*
