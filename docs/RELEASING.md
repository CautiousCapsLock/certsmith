# Releasing

How a change reaches a release. Written for the maintainer and for anyone running the pipeline on the
maintainer's behalf.

## Branches

| Branch | Purpose |
|---|---|
| `dev` | Where work lands. CI runs on every push. Builds from `dev` go to the development unit. |
| `main` | Released or releasable code only. Reached only by a pull request from `dev`. Releases are tagged on it. |

Dependabot pull requests target `main` and are merged there; bring them into `dev` with `git merge origin/main`.

## A change

1. Work on `dev`. Keep each commit to one concern, with the tests and documentation it needs.
2. Before pushing: `gofmt -l .`, `go vet ./...`, `go test -race ./...`, `sh scripts/check-docs.sh`,
   `sh scripts/check-private-addrs.sh`, `go run ./scripts/notices -check`, `sh scripts/test-install.sh` and
   `sh scripts/test-get.sh` (the CI job runs the same).
3. Push `dev`. Wait for CI to be green.

## A release

1. Choose the version `X.Y.Z` (semantic versioning: fixes and interface changes are a patch or minor release,
   anything that changes stored data or an installer option deserves a minor release).
2. Write the release notes as `internal/web/static/releases/vX.Y.Z.md`, in plain bullet points under headings
   (New, Improved, Fixed, Security). The program shows this file as "this version", and the release workflow
   publishes it as the GitHub release description. A stable tag without it is refused, in the first seconds of
   the run.
3. Commit it on `dev`, push, wait for CI to be green.
4. Open a pull request `dev` → `main`. Wait for the checks on the pull request, then merge with a merge commit.
5. Tag the merge commit on `main`:

```sh
git checkout main && git pull
git tag -a vX.Y.Z -m "CertSmith X.Y.Z: <one line>"
git push origin vX.Y.Z
```

6. The `release` workflow runs the tests, builds the amd64 and arm64 archives, attests them and publishes the
   release. Watch it finish.
7. Verify as an anonymous visitor: the release is not a draft, it has both archives and `SHA256SUMS`, the
   checksums match, and the attestation exists for the archive digest
   (`gh attestation verify <archive> --repo CautiousCapsLock/certsmith`).
8. Install the release on the development unit with the quick-install command from the README and check the
   version and Settings → Software → Release notes.
9. Bring `dev` level with `main`:

```sh
git checkout dev && git merge --ff-only origin/main && git push origin dev
```

   (`git merge origin/main` instead, if `main` gained commits of its own, such as a merged dependency update.)

## Pre-releases

A tag with a suffix (`v0.15.0-rc1`) is published as a pre-release, may go without a notes file (its notes are
generated from the commits), and is never offered as an update.

## Mistakes

- **Tagged without the notes file:** the workflow stops before building. Add the file on `dev`, merge, delete the
  tag (`git push origin :refs/tags/vX.Y.Z`, `git tag -d vX.Y.Z`) and tag again.
- **A bad release is already published:** delete the GitHub release and the tag, fix, and publish the next patch
  version. Do not reuse a version number: installations compare versions, and archives may already be cached.
