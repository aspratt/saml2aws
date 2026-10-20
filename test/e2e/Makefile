# saml2aws end-to-end harness. See README.md.
# One name per checkout: it sets the Compose project and every image name.
# Give each concurrent checkout its own, for example E2E_PROJECT=saml2aws-e2e-wi1994.
# Only names starting with saml2aws-e2e are allowed, so `down -v` cannot reach
# another stack on a shared Docker daemon.
E2E_PROJECT ?= saml2aws-e2e
ifneq ($(filter saml2aws-e2e%,$(E2E_PROJECT)),$(E2E_PROJECT))
$(error E2E_PROJECT must start with saml2aws-e2e, got '$(E2E_PROJECT)')
endif
export E2E_PROJECT
COMPOSE := docker compose -p $(E2E_PROJECT) -f docker-compose.yml
AWS_PROFILE ?=

.PHONY: all unit e2e e2e-aws aws-setup aws-teardown render build down clean

all: unit e2e

render:
	@scripts/render.sh

build: render
	$(COMPOSE) --profile unit --profile e2e --profile e2e-aws --profile tools build

# The repository's own unit tests, unchanged, in the runner image.
unit: build
	$(COMPOSE) run --rm unit

# Integration: Keycloak + moto standing in for STS.
e2e: build
	@set -e; trap '$(COMPOSE) down -v --remove-orphans >/dev/null 2>&1' EXIT; \
	$(COMPOSE) run --rm e2e

# Integration: Keycloak + real AWS STS. Needs AWS_PROFILE (SSO is fine).
e2e-aws:
	@test -n "$(AWS_PROFILE)" || { echo "set AWS_PROFILE=<profile>"; exit 2; }
	@set -e; \
	acct=$$(AWS_PROFILE=$(AWS_PROFILE) aws sts get-caller-identity --query Account --output text); \
	E2E_ACCOUNT_ID=$$acct scripts/render.sh; \
	$(COMPOSE) --profile e2e-aws --profile tools build; \
	trap '$(COMPOSE) down -v --remove-orphans >/dev/null 2>&1' EXIT; \
	$(COMPOSE) run --rm -T metadata > .work/idp-metadata.xml; \
	AWS_PROFILE=$(AWS_PROFILE) scripts/aws-setup.sh .work/idp-metadata.xml; \
	$(COMPOSE) run --rm e2e-aws

aws-teardown:
	@test -n "$(AWS_PROFILE)" || { echo "set AWS_PROFILE=<profile>"; exit 2; }
	AWS_PROFILE=$(AWS_PROFILE) scripts/aws-teardown.sh

down:
	$(COMPOSE) down -v --remove-orphans

clean: down
	rm -rf .work
