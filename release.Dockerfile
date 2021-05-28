FROM alpine:3.11

RUN apk --no-cache --no-progress add bash curl ca-certificates tzdata \
    && update-ca-certificates \
    && rm -rf /var/cache/apk/*

COPY dist/traefik /usr/local/bin/

COPY entrypoint.sh /

RUN chmod +x /usr/local/bin/traefik /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
CMD ["traefik"]
