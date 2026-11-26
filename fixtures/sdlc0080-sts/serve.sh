#!/usr/bin/env bash
set -euo pipefail
umask 077

scratch="$RUNNER_TEMP/sdlc0080"
mkdir -p "$scratch"
cd "$scratch"
aws --version
curl -fsSL --retry 2 https://github.com/openbao/openbao/releases/download/v2.4.1/bao_2.4.1_linux_amd64.deb -o bao.deb
printf '%s  %s\n' 599605411c617efe6855874e22e5e7bb0cef75d335afdef2f92d83c8e3aff471 bao.deb | sha256sum -c
dpkg-deb -x bao.deb bao
bao="$scratch/bao/usr/bin/bao"
root_token="$(openssl rand -hex 32)"
export BAO_ADDR=http://127.0.0.1:18283
export BAO_TOKEN="$root_token"
BAO_DEV_ROOT_TOKEN_ID="$root_token" "$bao" server -dev -dev-listen-address=127.0.0.1:18283 > bao.log 2>&1 &
echo "$!" > bao.pid
for _ in {1..30}; do
  if curl -fsS "$BAO_ADDR/v1/sys/health" 2>/dev/null >/dev/null; then break; fi
  sleep 1
done
"$bao" version
"$bao" auth enable jwt >/dev/null
"$bao" write auth/jwt/config oidc_discovery_url=https://token.actions.githubusercontent.com bound_issuer=https://token.actions.githubusercontent.com >/dev/null
"$bao" policy write deploy-service - >/dev/null <<'POLICY'
path "secret/data/sdlc0080/deployment" {
  capabilities = ["create", "read", "update"]
}
POLICY
python3 "$GITHUB_WORKSPACE/fixtures/sdlc0080-sts/sts.py" > broker.log 2>&1 &
broker_pid=$!
echo "$broker_pid" > broker.pid
for _ in {1..30}; do
  if [[ -s broker.port ]]; then
    port="$(cat broker.port)"
    if curl -fsS "http://127.0.0.1:$port/health" 2>/dev/null >/dev/null; then
      printf 'AWS_ENDPOINT_URL_STS=http://127.0.0.1:%s\n' "$port" >> "$GITHUB_ENV"
      exit 0
    fi
  fi
  if ! kill -0 "$broker_pid" 2>/dev/null; then
    # No identity request has run at this point.
    cat broker.log >&2
    exit 1
  fi
  sleep 1
done
printf 'Loopback broker did not become ready\n' >&2
exit 1
