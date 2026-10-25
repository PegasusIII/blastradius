FROM localhost/br-debian12
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends php8.2-cli php8.2-fpm libapache2-mod-php8.2 >/dev/null; rm -rf /var/lib/apt/lists/*
