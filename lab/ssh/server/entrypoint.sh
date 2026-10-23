#!/bin/sh
set -eu
umask 077
mkdir -p /run/lab /run/sshd
chmod 755 /run/lab /run/sshd
cp /lab/authorized_key /run/lab/authorized_keys
chmod 644 /run/lab/authorized_keys
ssh-keygen -q -t ed25519 -N '' -f /run/lab/ssh_host_ed25519_key
/usr/sbin/sshd -t
exec /usr/sbin/sshd -D -e
