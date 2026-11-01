#!/bin/sh
set -eu
if [ "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/cybershield360-managed ]; then
    /usr/sbin/nginx -t
    /usr/bin/systemctl reload nginx
fi
