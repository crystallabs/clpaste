# Static single-binary build on Alpine (musl), tiny runtime image.
FROM crystallang/crystal:1.20-alpine AS build
RUN apk add --no-cache sqlite-static sqlite-dev libxml2-static libxml2-dev yaml-static yaml-dev \
    zlib-static xz-static openssl-libs-static pcre2-dev
WORKDIR /src
COPY shard.yml shard.lock ./
RUN shards install --production
COPY . .
RUN shards build --production --release --static --no-debug && strip bin/clpaste

FROM alpine:3.20 AS paste
RUN apk add --no-cache ca-certificates && adduser -D -u 1000 clpaste && mkdir /data && chown clpaste /data
COPY --from=build /src/bin/clpaste /usr/local/bin/clpaste
USER clpaste
VOLUME /data
ENV CLPASTE_KEY_FILE=/data/clpaste.key CLPASTE_BIND=0.0.0.0 CLPASTE_PORT=8080
# SQLite lands in /data unless PG*/POSTGRES_* or CLPASTE_DB_URL are given.
ENV CLPASTE_DB_URL=sqlite3:///data/clpaste.db
EXPOSE 8080
HEALTHCHECK CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["clpaste"]
CMD ["serve"]

FROM paste
