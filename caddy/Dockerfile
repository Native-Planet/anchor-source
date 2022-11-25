FROM caddy:2.6.2-builder-alpine@sha256:735ad7b9a5ba5baf3df5f93034af5fa90c3554da9725d260df238d2511be6b23 AS builder
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