<!-- Process: docs/fork/PROCESS.md. One record per PR. -->

Closes #<record>  ·  Upstream: Versent/saml2aws#<n> (or "none")

## Classification
type: <bug|uplift|wishlist> · nature: <security|functional|gap> · severity: <S1–S4> · provider: <name>

## Change
<!-- What changed and why this is the smallest fix. Carried upstream commits keep their author; list them here. -->

## Test evidence (stage 3 → 6)
- Regression/risk test: `<package/TestName>` (or `test/e2e` test)
- Fails before the change: <CI link or pasted output, run on the baseline tag>
- Passes after the change: <CI link or pasted output>
- Exemption (docs-only / recorded fixtures only, with the missing live environment named): <none>

## Coverage
| Package | Before | After |
|---|---|---|
| | | |

## Gate
- [ ] `make -C test/e2e unit`
- [ ] `make -C test/e2e e2e`
- [ ] `make -C test/e2e e2e-aws AWS_PROFILE=<profile>`
- [ ] `golangci-lint run` (pinned version)
- [ ] Cross-compile: windows/amd64, darwin/arm64, linux/arm64
- [ ] Fork CI green

## Review
- [ ] Reviewed by someone other than the author
- [ ] Security review (if `nature:security`)
