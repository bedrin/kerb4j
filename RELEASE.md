# Release Process

This project uses GitHub Actions workflows from `.github/workflows`:
- `maven.yml` for CI build and test
- `deploy.yml` for publishing artifacts

## 1) Verify workflows before release

1. Confirm `maven.yml` is green on the target branch.
   - It runs `mvn -B clean package --file pom.xml -U`.
   - It is triggered by pushes to `master` and `develop`, pull requests, and manual dispatch.
2. Confirm `deploy.yml` is present and configured for release publishing.
   - It is triggered by `release: created` and manual dispatch.
   - It publishes with `mvn -P sonatype,release -B deploy` and `mvn -P github,release -B deploy`.
3. Ensure repository secrets required by `deploy.yml` are available:
   - `CENTRAL_USERNAME`
   - `CENTRAL_PASSWORD`
   - `GPG_PRIVATE_KEY`
   - `PASSPHRASE`

## 2) Prepare release contents

1. Update all module `pom.xml` versions from `*-SNAPSHOT` to the release version (for example `0.2.2`).
2. Update `CHANGES.md` with release notes for the new version.
3. Update any versioned documentation snippets, such as `README.md`.
4. Run local verification:
   - `mvn -B clean package --file pom.xml -U`

## 3) Publish release

1. Merge release-preparation changes to `master`.
2. Create a GitHub release with tag `<version>` from `master`.
   - `deploy.yml` is triggered by `release: created`.
3. Use the release notes from `CHANGES.md` as the GitHub release notes.
4. Monitor the `Publish package to the Maven Central Repository and GitHub Packages` workflow run.

## 4) Post-release checks

1. Verify artifacts are available on Maven Central.
2. Verify artifacts are available on GitHub Packages.
3. Confirm the tag and release notes are correct in GitHub Releases.
