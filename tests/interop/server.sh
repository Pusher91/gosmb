#!/bin/sh
set -eu

# Disposable fixture only. Keep the published port bound to 127.0.0.1.
dialect=${GOSMB_DIALECT:-SMB3_11}
encryption=${GOSMB_ENCRYPTION:-if_required}
bulk_shares=${GOSMB_BULK_SHARES:-0}
case "$dialect" in
    SMB2_02|SMB2_10|SMB3_00|SMB3_02|SMB3_11) ;;
    *) echo 'Unsupported GOSMB_DIALECT' >&2; exit 2 ;;
esac
case "$encryption" in
    off|if_required|desired|required) ;;
    *) echo 'GOSMB_ENCRYPTION must be off, if_required, desired, or required' >&2; exit 2 ;;
esac
case "$bulk_shares" in
    ''|*[!0-9]*|??????*) echo 'GOSMB_BULK_SHARES must be an integer from 0 to 16000' >&2; exit 2 ;;
esac
if [ "$bulk_shares" -gt 16000 ]; then
    echo 'GOSMB_BULK_SHARES must be an integer from 0 to 16000' >&2
    exit 2
fi

mkdir -p /etc/samba /run/samba /var/log/samba /var/lib/samba/private
for share in readwrite readonly guest encrypted denied writeonly; do
    mkdir -p "/shares/$share"
    printf 'gosmb independent fixture: %s\n' "$share" > "/shares/$share/seed.txt"
    chown -R audit-user:audit-user "/shares/$share"
    chmod 755 "/shares/$share"
    chmod 644 "/shares/$share/seed.txt"
done
chown -R nobody:nobody /shares/guest
chown -R root:root /shares/denied
chmod 700 /shares/denied
# The account can add a file and traverse this root but cannot list it.
chmod 300 /shares/writeonly

cat > /etc/samba/smb.conf <<EOF
[global]
    server role = standalone server
    workgroup = LAB
    netbios name = GOSMBTEST
    smb ports = 1445
    server min protocol = $dialect
    server max protocol = $dialect
    server signing = auto
    smb encrypt = $encryption
    map to guest = Bad User
    guest account = nobody
    load printers = no
    printing = bsd
    printcap name = /dev/null
    disable spoolss = yes
    log file = /var/log/samba/log.%m
    log level = 1
[readwrite]
    path = /shares/readwrite
    read only = no
    valid users = audit-user
[readonly]
    path = /shares/readonly
    read only = yes
    valid users = audit-user
[guest]
    path = /shares/guest
    read only = yes
    guest ok = yes
[encrypted]
    path = /shares/encrypted
    read only = no
    valid users = audit-user
    smb encrypt = required
[denied]
    path = /shares/denied
    read only = no
    valid users = audit-user
[writeonly]
    path = /shares/writeonly
    read only = no
    valid users = audit-user
EOF

bulk_comment=$(printf '%160s' '' | tr ' ' x)
index=1
while [ "$index" -le "$bulk_shares" ]; do
    {
        printf '[bulk-%04d]\n' "$index"
        printf '    path = /shares/readwrite\n'
        printf '    read only = no\n'
        printf '    valid users = audit-user\n'
        printf '    comment = %s\n' "$bulk_comment"
    } >> /etc/samba/smb.conf
    index=$((index + 1))
done

# Synthetic credentials used only inside this disposable lab.
printf '%s\n' validation-password validation-password | smbpasswd -s -a audit-user
testparm -s /etc/samba/smb.conf > /dev/null
exec smbd --foreground --no-process-group --configfile=/etc/samba/smb.conf
