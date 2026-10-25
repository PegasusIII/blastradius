FROM localhost/br-rocky9
RUN dnf -y -q install php-cli php-fpm python3-pip >/dev/null; dnf clean all >/dev/null
