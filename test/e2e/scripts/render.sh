#!/usr/bin/env bash
# Renders the throwaway material the e2e images are built from into .work/:
# a test CA plus a certificate for the STS hostnames, and the Keycloak realm.
#   E2E_ACCOUNT_ID  AWS account the SAML role attribute names (default: moto's)
set -euo pipefail
cd "$(dirname "$0")/.."
work=.work
mkdir -p "$work/certs"

account_id=${E2E_ACCOUNT_ID:-123456789012}
role_name=${E2E_ROLE_NAME:-saml2aws-e2e}
provider_name=${E2E_PROVIDER_NAME:-saml2aws-e2e}

if [[ ! -f $work/password ]]; then
  openssl rand -hex 16 > "$work/password"
fi

c=$work/certs
if [[ ! -f $c/ca.crt ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=saml2aws e2e test CA" \
    -keyout "$c/ca.key" -out "$c/ca.crt" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=sts.amazonaws.com" \
    -keyout "$c/sts.key" -out "$c/sts.csr" 2>/dev/null
  printf 'subjectAltName=DNS:sts.amazonaws.com,DNS:sts.us-east-1.amazonaws.com,DNS:sts.ap-southeast-2.amazonaws.com,DNS:signin.aws.amazon.com\n' > "$c/sts.ext"
  openssl x509 -req -in "$c/sts.csr" -CA "$c/ca.crt" -CAkey "$c/ca.key" -CAcreateserial \
    -days 30 -extfile "$c/sts.ext" -out "$c/sts.crt" 2>/dev/null
fi

sed -e "s/__ACCOUNT_ID__/$account_id/g" \
    -e "s/__ROLE_NAME__/$role_name/g" \
    -e "s/__PROVIDER_NAME__/$provider_name/g" \
    -e "s/__E2E_PASSWORD__/$(cat "$work/password")/g" \
    keycloak/realm.json.tmpl > "$work/realm.json"

cat > "$work/e2e.env" <<ENV
E2E_ACCOUNT_ID=$account_id
E2E_ROLE_ARN=arn:aws:iam::$account_id:role/$role_name
E2E_PRINCIPAL_ARN=arn:aws:iam::$account_id:saml-provider/$provider_name
E2E_PASSWORD=$(cat "$work/password")
ENV
echo "rendered .work/ for account $account_id"
