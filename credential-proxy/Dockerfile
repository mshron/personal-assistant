FROM caddy:2-alpine

RUN apk add --no-cache python3 su-exec

RUN adduser -D -H -s /sbin/nologin caddy \
    && adduser -D -H -s /sbin/nologin gmailproxy

COPY Caddyfile /etc/caddy/Caddyfile
COPY gmail-imap-proxy.py /opt/gmail-imap-proxy.py
COPY start-proxy.sh /opt/start-proxy.sh
RUN chmod +x /opt/start-proxy.sh

ENTRYPOINT ["/opt/start-proxy.sh"]
