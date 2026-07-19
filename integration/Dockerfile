# Alpine keeps SMB1 (NT1) server support compiled into its samba package;
# some distros build with --without-smb1-server, which would break these tests.
FROM alpine:3.24

# samba-client provides smbclient, used to verify the server accepts NT1.
RUN apk add --no-cache samba samba-client

# Test account expected by the integration suite (SMB_USER/SMB_PASSWORD).
RUN adduser -D -H -s /sbin/nologin smbtest \
    && printf 'smbtest\nsmbtest\n' | smbpasswd -a -s smbtest \
    && mkdir -p /srv/testshare \
    && chown smbtest:smbtest /srv/testshare

COPY smb.conf /etc/samba/smb.conf

EXPOSE 445

# Foreground with logs to stdout so `docker logs` shows smbd output.
CMD ["smbd", "--foreground", "--no-process-group", "--debug-stdout"]
