FROM alpine:3.23.4

# Samba is an independent test server/client, never a gosmb runtime dependency.
RUN apk add --no-cache samba-server samba-client samba-common-tools python3 \
    && adduser -D -H audit-user

COPY server.sh /usr/local/bin/gosmb-interop-server
COPY snapshot.py /usr/local/bin/gosmb-interop-snapshot
RUN chmod 755 /usr/local/bin/gosmb-interop-server /usr/local/bin/gosmb-interop-snapshot

EXPOSE 1445
ENTRYPOINT ["/usr/local/bin/gosmb-interop-server"]
