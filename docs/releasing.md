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
4. Create and publish a GitHub Release tagged exactly `vX.Y.Z`.
5. The `Publish to PyPI` workflow:
   - verifies the tag matches package metadata;
   - builds wheel + sdist;
   - runs `twine check`;
   - installs the built wheel in a clean virtual environment;
   - publishes with OIDC through the `pypi` GitHub environment.
6. Verify the PyPI page and install with:
   ```bash
   pipx install route-explain
   route-explain --version
   ```

## Why release publication is the trigger

Publishing a GitHub Release is an explicit operator action. Normal pushes, pull requests and tags cannot upload to PyPI.

## Rollback

PyPI release files are immutable. If a release is bad:

1. yank the affected release on PyPI;
2. fix the issue;
3. publish a new patch release.

Do not attempt to reuse an already-published version number.
