# Releasing to PyPI

route-explain uses GitHub Actions Trusted Publishing (OIDC). No long-lived PyPI token belongs in GitHub secrets.

## One-time PyPI setup

Before the first release, sign in to PyPI and create a **pending GitHub Trusted Publisher** with:

- PyPI project name: `route-explain`
- GitHub owner: `artur-panek`
- GitHub repository: `route-explain`
- Workflow filename: `publish.yml`
- Environment name: `pypi`

A pending publisher creates the project on its first successful publish. It does **not** reserve the name before that first publish.

## Release checklist

1. Ensure `main` CI is green.
2. Ensure `pyproject.toml` and `route_explain.__version__` contain the same version.
3. Move release notes from `Unreleased` into a versioned changelog section.
4. After publication approval, create `release/vX.Y.Z` from the exact tested commit. Pushing this branch triggers publication; the branch must match the package version.
5. The workflow builds wheel + sdist, checks metadata, smoke-tests the installed wheel, publishes through the `pypi` OIDC environment, then creates the matching GitHub Release.
6. Verify `route-explain --version` from a fresh installation.

Normal PR branches, main pushes and manually created tags/releases do not upload to PyPI. Candidate branches deliberately use a different name. Do not create a `release/v*` branch while merely preparing a candidate.

## Rollback

PyPI release files are immutable. If a release is bad:

1. yank the affected release on PyPI;
2. fix the issue;
3. publish a new patch release.

Do not attempt to reuse an already-published version number.
