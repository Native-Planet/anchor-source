FROM caddy/caddy:2.6.4-builder-alpine@sha256:edd012bd8bff31135bb4eddec716e22501e0e8041d9b9d578418bb65197309b4 AS builder
RUN xcaddy build \
    --with github.com/caddy-dns/cloudflare@latest
FROM caddy:2.6-alpine@sha256:7992b931b7da3cf0840dd69ea74b2c67d423faf03408da8abdc31b7590a239a7
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY ./default_config.json /etc/caddy/
RUN apk add curl
RUN echo "#!/bin/ash" > /init
RUN echo "ip route add 10.13.13.0/24 via 172.20.0.2" >> /init
RUN echo "exec /usr/bin/caddy run --config /etc/caddy/default_config.json --resume" >> /init
RUN chmod +x /init
EXPOSE 80
EXPOSE 443
CMD ["ash", "/init"]