# Change process for this fork

This fork of [Versent/saml2aws](https://github.com/Versent/saml2aws) is
maintained for people who depend on saml2aws to reach AWS. Every change, whether
our own or carried from an upstream issue or PR, goes through the same cycle,
in order. A stage is finished only when its exit check is met.

**Records live as Issues on this fork.** Each record links the upstream issue
or PR it comes from. Security problems never get a public issue; see
[Security items](#security-items).

## The cycle

| # | Stage | What happens | Exit check | `status:` label |
|---|---|---|---|---|
| 1 | Intake | Open a record with the matching issue form. Link every upstream issue/PR it covers and paste the upstream text into the record, since upstream may change or delete it. Fold duplicates into one record. | Record exists; upstream links listed | `status:intake` |
| 2 | Classify | Set **type**, **nature**, **severity** and **provider** labels (below). | One label of each set | `status:classified` |
| 3 | Reproduce | Complete the template on a **named baseline tag**. Commit a test that fails because of the problem. | Failing test on a branch, linked from the record, **or** a written reason it can't be reproduced yet | `status:reproduced` / `status:needs-repro` |
| 4 | Decide | The maintainer accepts, defers, declines or marks it a duplicate, and writes down why. | Decision and reason in the record | `status:accepted` / `status:deferred` / `status:wontfix` / `status:duplicate` |
| 5 | Change | One record per branch (`<type>/<issue#>-<slug>`), cut from current `master`. Make the smallest change that fixes it. | The stage-3 test passes | `status:in-progress` |
| 6 | Verify | Run the full gate (below) and link the evidence in the PR. | Every gate passes | `status:in-review` |
| 7 | Review | **Fork:** an independent AI review, by a different model from the one that wrote the change and never Haiku, posts its findings on the PR. The maintainer then approves the merge. Security items also get a second review focused on security. **Upstream:** a second Versent maintainer reviews and accepts (below). | Findings addressed; maintainer approved (fork) or second maintainer approved (upstream) | `status:in-review` |
| 8 | Release | Merge to `master` with the PR closing the record. Changes are released under a release tag. Offer the change upstream (below). | Merged; record closed; upstream PR linked or a reason given | `status:done` |

Moving backwards is normal. If verify or review fails, go back to stage 5.
If the fix changes the problem's scope, go back to stage 2.

## Who does what

Oversight is the maintainer's session. Workers are the sessions that make a
change. Each worker session is bound to one record.

- **Oversight** keeps the records, makes the stage-4 decisions, commits,
  pushes to the fork, runs the `e2e-aws` gate and handles releases.
- **Workers** (Haiku sessions) edit and test in their own git worktree, then
  hand off the diff summary and test evidence. They never commit, push or tag,
  and never post to GitHub. Each worktree sets its own `E2E_PROJECT` before
  running the harness (see `test/e2e/README.md`), so parallel runs don't
  collide.
- **Commits** are made by oversight as **aspratt**, with no AI attribution:
  no `Co-Authored-By` trailers and no "Generated with" lines, in commits, PR
  text or comments.
- **`e2e-aws`** runs serially through oversight only. The AWS SAML provider is
  shared, so parallel runs interfere with each other and with other users.
- **Stage-7 reviews** are done by an AI model other than the author's (never
  Haiku), then approved by the maintainer. See stage 7 above.

## Classification

Each record gets exactly one label from each of these sets.

**Type**
- `type:bug`: saml2aws does something wrong that it is meant to do right.
- `type:uplift`: toolchain, dependency, CI or platform currency. Nothing is
  broken for users yet, or it breaks because the world around saml2aws moved
  (for example, a retired CDN).
- `type:wishlist`: a new capability or behaviour.

**Nature**
- `nature:security`: confidentiality, integrity or credential safety: secrets
  handling, a vulnerable dependency, token predictability.
- `nature:functional`: something that exists and should work.
- `nature:gap`: an IdP, flow or platform that saml2aws doesn't support yet
  (for example, Duo Universal Prompt or modern PingOne).

**Severity**

| Label | Meaning | Example |
|---|---|---|
| `severity:S1` | Security exposure, or login broken for everyone on a provider, with no workaround | Credential leak; AAD error 50203 for all Entra users |
| `severity:S2` | Login broken for a common configuration, or a workaround exists but is hard | Keycloak 26 wrong-password loop; browser provider dead on fresh installs |
| `severity:S3` | Degraded or wrong behaviour with an easy workaround | `list-roles` empty for single-role users |
| `severity:S4` | Cosmetic, docs, or a minor annoyance | Misleading error text |

**Provider**: `provider:<name>`, using the directory names under
`pkg/provider/` (for example `provider:keycloak`), plus `provider:core` for the
CLI, config and credential code and `provider:build` for build, CI and
packaging.

Work order: severity first, then the number of users affected (upstream
reactions and duplicates), then whether a test environment exists.

## Impacted version

State it two ways in the record:
- **Upstream:** the first and last upstream releases known to be affected
  (for example `v2.36.0 – v2.36.19`, or `unknown – v2.36.19`).
- **Confirmed on:** the fork tag where we reproduced it (for example
  `golang-uplift-baseline`). An item reported upstream but never reproduced
  here says `not reproduced` and stays `status:needs-repro`.

## Test rules

1. **Bug:** add a regression test that **fails before** the change and
   **passes after**. The PR links both runs: the stage-3 failing run and the
   stage-6 passing run.
2. **Uplift:** the full gate must pass, **plus** a test for the specific risk
   the uplift carries (for example, a Windows keychain round-trip for a
   `wincred` bump).
3. **Wishlist/gap:** add tests for the new behaviour at the lowest level that
   can exercise it, and an integration test when the harness can drive it.
4. **Provider or IdP flows with no live test environment:** the minimum is a
   unit test that replays recorded HTML/JSON from the IdP, with secrets
   removed, stored under the provider's `testdata/`. The record says which
   live environment is missing, and a live test is added once one exists.
5. **Docs-only changes** are exempt from 1–4 but still go through review.
6. **Coverage:** no package's `go test -cover` percentage may go down. The PR
   shows the before and after numbers for every package it touches.
7. **Known bugs** are tests that are skipped unless `E2E_KNOWN_BUGS=1` (see
   `test/e2e`). Fixing one means removing the skip so the test becomes
   required.

## The gate (stage 6)

All of these must pass, with the output or CI links in the PR:

| Gate | Command |
|---|---|
| Unit | `make -C test/e2e unit` |
| Integration (moto) | `make -C test/e2e e2e` |
| Integration (real AWS STS) | `make -C test/e2e e2e-aws AWS_PROFILE=<profile>` |
| Lint | `golangci-lint run` (the version pinned in `.github/workflows/go.yml`) |
| Cross-compile | `GOOS=windows`, `GOOS=darwin`, `GOARCH=arm64` builds of `./cmd/saml2aws` |
| Fork CI | the `Go` workflow on the PR is green |

## Labels vs git tags

- **Labels** classify and track records (the sets above, plus `status:`).
- **Git tags** mark verified states of `master` only:
  - **Baselines** (`baseline`, `golang-uplift-baseline`, …) record a tested
    reference point that work is measured against.
  - **Releases** are tagged `v2.37.0-fork.<n>` (`v2.37.0-fork.1`, …), and
    only on a commit where the full gate passed. They sort after upstream
    `v2.36.19`, and read as pre-releases of the `v2.37.0` we intend to send
    upstream.
- **Warning:** `.github/workflows/release.yml` runs on **every** tag push and
  publishes a GitHub release plus ghcr images. It is **disabled on the fork**
  until the first fork release is ready. Don't re-enable it without deciding
  the release flow first.

## Upstream

Everything is meant to go back to Versent/saml2aws, but only as a **stable
fork release**, never item by item. The fork comes first and nothing waits on
upstream.

**Before the upstream release, upstream is read-only.**
- Snapshot upstream issues/PRs into fork records, and re-sync weekly to pick
  up new items.
- No comments, labels, closes or pushes upstream. Exception: a security
  report gets a private reply.
- The maintainer account has push rights upstream and upstream `master` is
  unprotected, so local clones disable pushing to the upstream remote:
  `git remote set-url --push origin DISABLED-use-a-PR-from-the-fork`.
  Never push tags upstream. Any tag there publishes a release, including
  `ghcr.io/versent/saml2aws:latest`.

**Carrying a contributor's upstream PR.** Cherry-pick their commits with
their authorship kept, then add our tests and fixes as **separate** commits.
The record names the upstream PR and its author.

**The upstream release.** Once a fork release has passed the full gate:
1. Open one upstream PR per record (or per tightly coupled group), cut from
   upstream `master`. Leave out fork-only files: `docs/fork/`,
   `.github/ISSUE_TEMPLATE/`, and fork workflow changes.
2. A **second Versent maintainer** reviews and merges. The author never
   merges their own upstream PR.
3. Close upstream items through the PRs themselves:
   - **Fixed issues:** the PR says `Fixes #n`, and the issue closes on merge
     with a comment naming the release.
   - **Carried PRs:** merge the contributor's PR with our test commits added,
     or close it in favour of ours with a comment crediting them.
   - **Declined PRs:** a specific, polite reason with a link to the record.
     Never a bulk close.
   - **Stale or duplicate issues:** closed in batches only when the second
     maintainer agrees, with a standard comment inviting a reopen with a
     reproduction on the new release.
4. Each record links its upstream PR, or says why it wasn't sent (for
   example, it depends on a fork-only change).

## Security items

- Report them through **private vulnerability reporting** on this fork
  (Security → Advisories). Never open a public issue for one.
- They follow the same cycle inside the advisory, and the fix is reviewed
  privately.
- Publish the advisory, and the upstream report if it applies to upstream,
  only once the fixed release is tagged.
- Vulnerable dependencies that are already public (a published CVE) may use a
  normal `nature:security` issue, because the information is already out.
