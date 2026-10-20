# saml2aws end-to-end harness. See README.md.
COMPOSE := docker compose -f docker-compose.yml
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
	@trap '$(COMPOSE) down -v --remove-orphans >/dev/null 2>&1' EXIT; \
	$(COMPOSE) run --rm e2e

# Integration: Keycloak + real AWS STS. Needs AWS_PROFILE (SSO is fine).
e2e-aws:
	@test -n "$(AWS_PROFILE)" || { echo "set AWS_PROFILE=<profile>"; exit 2; }
	@acct=$$(AWS_PROFILE=$(AWS_PROFILE) aws sts get-caller-identity --query Account --output text) && \
	rm -f .work/realm.json && E2E_ACCOUNT_ID=$$acct scripts/render.sh && \
	$(COMPOSE) --profile e2e-aws --profile tools build && \
	trap '$(COMPOSE) down -v --remove-orphans >/dev/null 2>&1' EXIT; \
	$(COMPOSE) run --rm -T metadata > .work/idp-metadata.xml && \
	AWS_PROFILE=$(AWS_PROFILE) scripts/aws-setup.sh .work/idp-metadata.xml && \
	$(COMPOSE) run --rm e2e-aws

aws-teardown:
	@test -n "$(AWS_PROFILE)" || { echo "set AWS_PROFILE=<profile>"; exit 2; }
	AWS_PROFILE=$(AWS_PROFILE) scripts/aws-teardown.sh

down:
	$(COMPOSE) down -v --remove-orphans

clean: down
	rm -rf .work
