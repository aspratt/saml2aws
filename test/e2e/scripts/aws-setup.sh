#!/usr/bin/env bash
# Creates (or refreshes) the real-AWS side of the harness in the account that
# AWS_PROFILE points at: an IAM SAML provider trusting the e2e Keycloak realm,
# and a role with NO permissions that only that provider can assume.
#   usage: AWS_PROFILE=<profile> scripts/aws-setup.sh <idp-metadata.xml>
set -euo pipefail
: "${AWS_PROFILE:?set AWS_PROFILE to the account the harness may use}"
metadata=${1:?idp metadata file}
name=${E2E_PROVIDER_NAME:-saml2aws-e2e}
role=${E2E_ROLE_NAME:-saml2aws-e2e}
account=$(aws sts get-caller-identity --query Account --output text)
provider_arn="arn:aws:iam::$account:saml-provider/$name"
tags=(Key=purpose,Value=saml2aws-e2e)

if aws iam get-saml-provider --saml-provider-arn "$provider_arn" >/dev/null 2>&1; then
  aws iam update-saml-provider --saml-provider-arn "$provider_arn" \
    --saml-metadata-document "file://$metadata" >/dev/null
  echo "updated $provider_arn"
else
  aws iam create-saml-provider --name "$name" --tags "${tags[@]}" \
    --saml-metadata-document "file://$metadata" >/dev/null
  echo "created $provider_arn"
  provider_created=1
fi

created=${provider_created:-0}
trust=$(cat <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
 "Principal":{"Federated":"$provider_arn"},
 "Action":"sts:AssumeRoleWithSAML",
 "Condition":{"StringEquals":{"SAML:aud":"https://signin.aws.amazon.com/saml"}}}]}
JSON
)
if aws iam get-role --role-name "$role" >/dev/null 2>&1; then
  aws iam update-assume-role-policy --role-name "$role" --policy-document "$trust"
  echo "updated role $role"
else
  aws iam create-role --role-name "$role" --tags "${tags[@]}" --max-session-duration 3600 \
    --description "saml2aws e2e harness: no permissions, SAML-only trust" \
    --assume-role-policy-document "$trust" >/dev/null
  echo "created role $role"
  created=1
fi
# A new role or provider takes a few seconds to reach STS and the sign-in
# endpoint; the first AssumeRoleWithSAML otherwise gets AccessDenied.
if [[ $created == 1 ]]; then
  aws iam wait role-exists --role-name "$role"
  echo "waiting 20s for IAM propagation"
  sleep 20
fi
echo "$account"
