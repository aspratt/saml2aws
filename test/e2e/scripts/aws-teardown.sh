#!/usr/bin/env bash
# Removes what aws-setup.sh created. Refuses to touch a role that has gained
# policies, so it never deletes something it did not make.
#   usage: AWS_PROFILE=<profile> scripts/aws-teardown.sh
set -euo pipefail
: "${AWS_PROFILE:?set AWS_PROFILE}"
name=${E2E_PROVIDER_NAME:-saml2aws-e2e}
role=${E2E_ROLE_NAME:-saml2aws-e2e}
account=$(aws sts get-caller-identity --query Account --output text)

if aws iam get-role --role-name "$role" >/dev/null 2>&1; then
  attached=$(aws iam list-attached-role-policies --role-name "$role" --query 'length(AttachedPolicies)')
  inline=$(aws iam list-role-policies --role-name "$role" --query 'length(PolicyNames)')
  if [[ $attached != 0 || $inline != 0 ]]; then
    echo "role $role has policies attached; not deleting it" >&2; exit 1
  fi
  aws iam delete-role --role-name "$role" && echo "deleted role $role"
fi
arn="arn:aws:iam::$account:saml-provider/$name"
if aws iam get-saml-provider --saml-provider-arn "$arn" >/dev/null 2>&1; then
  aws iam delete-saml-provider --saml-provider-arn "$arn" && echo "deleted $arn"
fi
