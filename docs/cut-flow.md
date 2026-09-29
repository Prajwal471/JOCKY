# Cut flow

A *cut* is the moment a tree stops being work in progress and becomes a
version somebody can hold you to. This document is the procedure for making
one, and the rules that make the procedure worth anything.

## The rule the cut exists to enforce

> A cut is a claim that every result the repository documents is reproducible
> from the tree being cut.

`python -m jocky.release --check` is the executable form of that claim. It
re-derives each documented result from the code in the working tree, and exits
non-zero if any of them stops holding. **A red check blocks the cut.** There is
no `--force`, because a release that can be forced is not a gate.

## The gates

| Gate | What it proves | Fails when |
| --- | --- | --- |
| `version` | `pyproject.toml` and `CHANGELOG.md` agree | the changelog has no entry for the current version |
| `examples` | every shipped mission parses, lowers to JIR, and pins deterministically | an example stops compiling, or its digest drifts |
| `front-end-fails-closed` | five invalid programs are refused, each as a `JockySyntaxError` | a refusal is removed, or an error escapes as a library type |
| `capability-registry` | the grantable and never-grant sets are disjoint and enforced | a capability is both grantable and never-grant, or a never-grant capability is accepted |
| `active-measures` | all five measures pass and each states a claim, a limit and its evidence | a measure passes vacuously, or one stops reporting what it does not prove |
| `baseline-matrix` | all seven baselines pass with every expectation satisfied | a baseline regresses, or the catalogue shrinks |
| `interop-invariants` | chain continuity, coverage, decisions, JIR stability, linkage and signature verification all hold | any invariant reports `status: broken` |
| `auth` | both mutating routes refuse a missing, wrong, and *unset* token, and accept a valid one | `POST /missions` or `POST /measures/run` returns anything but 401 to an unauthenticated caller, or a valid token is rejected |
| `git` | the tree is committed and on `master` | there are uncommitted changes (`--allow-dirty` to override) |
| `tests` | the suite passes | anything fails (`--with-tests`; off by default because the suite is slow) |

The gates run in `sample` mode against a throwaway SQLite database, so a cut
check needs neither PostgreSQL nor a network. `--live` opts into real host
reads; a live cut check is a stronger claim and is what the runbook's step 1
should be run with on a Windows host before a real release.

## Procedure

**1. Make the tree honest.** Every claim you intend to ship must already be
true. If a result changed, the documentation and `CHANGELOG.md` change in the
same commit as the code — a cut never repairs documentation.

**2. Check.**

```sh
python -m jocky.release --check --with-tests
```

**3. Check against the real host**, if the release claims live behaviour:

```sh
python -m jocky.release --check --live --allow-dirty
```

**4. Update the changelog.** The version in `pyproject.toml` must have a
`## <version>` heading, or the `version` gate fails.

**5. Commit.** One commit per block, tests green. The `git` gate refuses a
dirty tree.

**6. Tag.** The gate refuses a tag that does not match `pyproject.toml`, so the
tag can never disagree with the package:

```sh
python -m jocky.release --tag 0.2.0
# git tag -a v0.2.0 -m 'JOCKY 0.2.0'
```

**7. Push the commit, then the tag.**

```sh
git push origin master
git push origin v0.2.0
```

**8. Re-verify on the tagged tree.** The commit you tested is not always the
commit you shipped. Check out the tag into a throwaway clone and re-run the cut
there, so the verification belongs to the release rather than to the
working tree it came from:

```sh
git clone --branch v0.2.0 --depth 1 . /tmp/jocky-verify
cd /tmp/jocky-verify && python -m jocky.release --check --with-tests
```

## What a cut must not contain

- **A number without a command.** If a figure appears in the README or the
  docs, `docs/implementation-status.md` must name the command that produces it.
  Wall-clock timings are exempt precisely because they are never persisted and
  never presented as results.
- **A performance claim.** Not until a lab exists to measure across
  configurations. A single-host number is not a portable one.
- **A capability without a gate.** Every entry in the capability registry must
  appear in a baseline or a measure, or it is unevaluated surface area.
- **A silently widened scope.** If a block could not be finished, the changelog
  says so and `docs/implementation-status.md` records the claim as *Absent*.

## After the cut

Re-run the check on the tagged tree. If a gate that was green at cut time is red
afterwards, the tag is wrong: cut a patch version rather than amending, so the
history shows what was believed and when.
