#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Nicholas Honeth
# Enrol a cert-only OpenTAKServer client (service account, bridge, script).
# The private key is generated here and never leaves this host; only the CSR goes to the server.
#
# Usage: tools/ots-client-cert.sh [--create-user] NAME [OUTDIR]
#   NAME           OTS username = cert CN (OTS identifies the device by the CN)
#   OUTDIR         where NAME.key, NAME.pem and ca.pem go (default: ./NAME, created mode 700)
#   --create-user  also create the OTS user NAME (random password, never used)
#
# Environment:
#   OTS_SSH        ssh target of the OTS host        (required)
#   OTS_DIR        compose project dir on that host   (default: ~/tak)
#   OTS_SERVICE    compose service running OTS        (default: ots)
#   CERT_DAYS      validity in days                   (default: 730)
#   CERT_SUBJ_EXTRA  extra subject fields             (default: /O=HonethTAKLab/OU=OpenTAKServer)
set -euo pipefail

case ${1:-} in -h|--help|"") sed -n '4,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;; esac
create_user=0
if [[ ${1:-} == --create-user ]]; then create_user=1; shift; fi
name=${1:?usage: $0 [--create-user] NAME [OUTDIR]}
outdir=${2:-./$name}
[[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { echo "NAME may only contain letters, digits, . _ -" >&2; exit 1; }

ssh_host=${OTS_SSH:?set OTS_SSH to the ssh target of the OTS host}
ots_dir=${OTS_DIR:-'~/tak'}
svc=${OTS_SERVICE:-ots}
days=${CERT_DAYS:-730}
subj_extra=${CERT_SUBJ_EXTRA:-/O=HonethTAKLab/OU=OpenTAKServer}

compose() { ssh "$ssh_host" "cd $ots_dir && docker compose exec -T $*"; }

mkdir -p "$outdir" && chmod 700 "$outdir"
cd "$outdir"

if (( create_user )); then
  echo "Creating OTS user $name on $ssh_host"
  compose "-w /data/ots $svc /opt/venv/bin/python -" <<EOF
import secrets
from flask_security.utils import hash_password
from opentakserver.app import create_app
from opentakserver.extensions import db
app = create_app(cli=True)
with app.app_context():
    ds = app.security.datastore
    if ds.find_user(username="$name"):
        print("user $name already exists")
    else:
        ds.create_user(username="$name", password=hash_password(secrets.token_urlsafe(24)), active=True, roles=["user"])
        db.session.commit()
        print("created user $name")
EOF
fi

if [[ -e $name.key ]]; then
  echo "Reusing existing $outdir/$name.key"
else
  (umask 077; openssl req -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" -subj "/CN=$name$subj_extra")
fi
[[ -e $name.csr ]] || openssl req -new -key "$name.key" -out "$name.csr" -subj "/CN=$name$subj_extra"

echo "Signing $name.csr with the OTS CA on $ssh_host ($days days, clientAuth)"
compose "$svc sh -c '
  set -e
  cat > /tmp/in.csr
  printf \"basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n\" > /tmp/ext.cnf
  mkdir -p /data/ots/ca/certs/$name
  openssl x509 -req -in /tmp/in.csr -CA /data/ots/ca/ca.pem -CAkey /data/ots/ca/ca-do-not-share.key \
    -passin pass:\$OTS_CA_PASSWORD -CAcreateserial -days $days -sha256 -extfile /tmp/ext.cnf \
    -out /data/ots/ca/certs/$name/$name.pem 2>/dev/null
  rm -f /tmp/in.csr /tmp/ext.cnf
  cat /data/ots/ca/certs/$name/$name.pem'" < "$name.csr" > "$name.pem.tmp"
mv "$name.pem.tmp" "$name.pem"
compose "$svc cat /data/ots/ca/ca.pem" > ca.pem

openssl verify -CAfile ca.pem "$name.pem"
openssl x509 -in "$name.pem" -noout -subject -enddate
chmod 600 "$name.key"
echo "Done: $(pwd)/{$name.key,$name.pem,ca.pem}"
