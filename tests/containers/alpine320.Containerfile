FROM docker.io/library/alpine:3.20
RUN apk add -q --no-cache openssl python3 strace && adduser -D bruser
