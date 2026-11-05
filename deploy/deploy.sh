#!/bin/sh
# Deploy pki.encedo.com and attest.encedo.com on the attest host from this checkout.
#
#   cd /opt/attest-pki-website && git pull && deploy/deploy.sh [all|pki|nginx|attest|refresh]
#
#   pki      copy pki.encedo.com/ to the web root (after checking SHA256SUMS)
#   nginx    install the nginx configs from deploy/nginx/, test, reload (rolls back on a failed test)
#   attest   build the image from attest.encedo.com/, refresh the data, replace the container
#            (the previous container is started again if the new one does not answer)
#   refresh  sync the PKI from https://pki.encedo.com and rebuild the SKID index (cron, daily)
#   all      pki + nginx + attest (default)
#
# Runs as root. Data outside the repo, in $DATA:
#   issued/*.pem   device certificates issued by the Encedo Custody CA (not in git; copied from the CA)
#   revoked.txt    revoked device SKIDs, one per line (may be empty)
#   pki/ crl/      written by tools/sync_pki.php
#   data/          index.sqlite, written by tools/build_index.php
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
DATA=${ATTEST_DATA_DIR:-/srv/attest}
WEB_PKI=/var/www/pki.encedo.com
IMAGE=attest-service
NAME=attest
PORT=127.0.0.1:8080
# the image runs as nobody
UID_NOBODY=65534

log() { echo "[deploy] $*"; }

deploy_pki() {
    log "pki: checking SHA256SUMS"
    (cd "$REPO/pki.encedo.com" && sha256sum --quiet -c SHA256SUMS)
    mkdir -p "$WEB_PKI"
    for f in "$REPO"/pki.encedo.com/*; do install -m 644 "$f" "$WEB_PKI/"; done
    log "pki: $(ls "$REPO/pki.encedo.com" | wc -l) files in $WEB_PKI"
}

deploy_nginx() {
    N=/etc/nginx
    # backups go outside sites-enabled/ and conf.d/: nginx loads every file there
    BK=/root/nginx-backup-$(date +%Y%m%d-%H%M%S)
    mkdir -p "$BK"
    for f in sites-available/pki.encedo.com sites-available/attest.encedo.com \
             conf.d/attest-limits.conf snippets/pki-types.conf snippets/attest-proxy.conf; do
        [ -f "$N/$f" ] && cp -p "$N/$f" "$BK/$(echo "$f" | tr / _)"
    done
    install -m 644 "$REPO/deploy/nginx/pki.encedo.com.conf"    "$N/sites-available/pki.encedo.com"
    install -m 644 "$REPO/deploy/nginx/attest.encedo.com.conf" "$N/sites-available/attest.encedo.com"
    install -m 644 "$REPO/deploy/nginx/attest-limits.conf"     "$N/conf.d/attest-limits.conf"
    install -m 644 "$REPO/deploy/nginx/pki-types.conf"         "$N/snippets/pki-types.conf"
    install -m 644 "$REPO/deploy/nginx/attest-proxy.conf"      "$N/snippets/attest-proxy.conf"
    ln -sf ../sites-available/pki.encedo.com    "$N/sites-enabled/pki.encedo.com"
    ln -sf ../sites-available/attest.encedo.com "$N/sites-enabled/attest.encedo.com"
    if nginx -t 2>/dev/null; then
        systemctl reload nginx
        log "nginx: reloaded (previous files in $BK)"
    else
        nginx -t || true
        log "nginx: test FAILED, restoring $BK"
        for b in "$BK"/*; do
            [ -e "$b" ] || continue
            cp -p "$b" "$N/$(basename "$b" | tr _ /)"
        done
        [ -f "$BK/conf.d_attest-limits.conf" ] || rm -f "$N/conf.d/attest-limits.conf"
        [ -f "$BK/snippets_attest-proxy.conf" ] || rm -f "$N/snippets/attest-proxy.conf"
        nginx -t && systemctl reload nginx
        exit 1
    fi
}

tool() {  # run a tool of the image against $DATA, writable
    docker run --rm -e ATTEST_DATA=/data -v "$DATA:/data" "$IMAGE:latest" php "$@"
}

refresh() {
    mkdir -p "$DATA/issued" "$DATA/pki" "$DATA/crl" "$DATA/data"
    [ -f "$DATA/revoked.txt" ] || : > "$DATA/revoked.txt"
    chown -R "$UID_NOBODY:$UID_NOBODY" "$DATA/pki" "$DATA/crl" "$DATA/data"
    tool tools/sync_pki.php https://pki.encedo.com
    tool tools/build_index.php /data/issued /data/revoked.txt /data/data/index.sqlite
}

smoke() {  # the container answers and has the PKI and the index
    i=0
    while [ $i -lt 20 ]; do
        if curl -fsS "http://$PORT/v1/pki" 2>/dev/null | grep -q '"certificates":\[{' &&
           curl -fsS "http://$PORT/v1/skid/0000000000000000000000000000000000000000" 2>/dev/null | grep -q '"known":false'; then
            return 0
        fi
        i=$((i + 1)); sleep 1
    done
    return 1
}

deploy_attest() {
    REV=$(git -C "$REPO" rev-parse --short HEAD)
    log "attest: building $IMAGE:$REV"
    docker build -q -t "$IMAGE:$REV" "$REPO/attest.encedo.com" >/dev/null
    # by image ID: the tag :latest is about to point at the new build
    PREV=$(docker inspect -f '{{.Image}}' "$NAME" 2>/dev/null || true)
    docker tag "$IMAGE:$REV" "$IMAGE:latest"
    refresh
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    run_container "$IMAGE:$REV"
    if smoke; then
        install -m 644 "$REPO/deploy/attest-refresh.cron" /etc/cron.d/attest-refresh
        log "attest: $IMAGE:$REV up on $PORT, daily refresh in /etc/cron.d/attest-refresh"
    else
        log "attest: $IMAGE:$REV does not answer"
        docker logs --tail 20 "$NAME" || true
        if [ -n "$PREV" ] && [ "$PREV" != "$(docker inspect -f '{{.Id}}' "$IMAGE:$REV")" ]; then
            log "attest: back to $PREV"
            docker rm -f "$NAME" >/dev/null 2>&1 || true
            docker tag "$PREV" "$IMAGE:latest"
            run_container "$PREV"
        fi
        exit 1
    fi
}

run_container() {
    # loopback only: a port published on 0.0.0.0 by Docker bypasses ufw
    docker run -d --name "$NAME" --restart unless-stopped \
        -p "$PORT:8080" \
        -v "$DATA:/data:ro" \
        --read-only --tmpfs /tmp:size=16m \
        --cap-drop ALL --security-opt no-new-privileges \
        --memory 256m --pids-limit 64 \
        "$1" >/dev/null
}

case "${1:-all}" in
    pki)     deploy_pki ;;
    nginx)   deploy_nginx ;;
    attest)  deploy_attest ;;
    refresh) refresh ;;
    all)     deploy_pki; deploy_attest; deploy_nginx ;;
    *)       echo "usage: $0 [all|pki|nginx|attest|refresh]" >&2; exit 2 ;;
esac
