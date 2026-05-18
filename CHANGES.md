# Changelog

All notable changes to this project are documented in this file.

## 0.2.1

### Build and release
- Migrated publishing from OSSRH to Maven Central Portal using `central-publishing-maven-plugin`.
- Updated GitHub Actions publishing workflow to use the new Central credentials and server id.
- Finalized all module versions to `0.2.1` for release.

### Dependencies
- Applied Maven dependency minor/patch updates via Dependabot (including Apache Kerby, SLF4J, Mockito, and other test/build dependencies).

## 0.2.0

### Enhancements
- Added support for Jakarta EE.

### Dependency upgrades
- Updated Apache Kerby to `2.0.3`.

### Notes
- Java 17 became the minimum required version for `0.2.x`.

## 0.1.4

### Dependency upgrades
- Updated Apache Kerby to `2.0.3`.
