# Changelog

All notable changes to this project are documented in this file.

## 0.3.0

### Release preparation
- Finalized all module versions to `0.3.0` for release publishing.

### Dependencies
- Updated `org.springframework.boot` from `3.1.4` to `4.0.6`.

## 0.2.3

### Build and release
- Documented the release process in `RELEASE.md`.
- Updated Dependabot configuration to align Spring/Tomcat dependency updates behind the Spring Boot BOM.

### Dependencies
- Updated `org.sonatype.central:central-publishing-maven-plugin` from `0.7.0` to `0.10.0`.

## 0.2.2

### Release preparation
- Finalized all module versions to `0.2.2` for release publishing.

### Dependencies
- Updated the shared Spring stack via PR `#94`, including `org.springframework.boot` from `3.1.4` to `3.5.14`, shared `org.springframework.security` from `6.1.5` to `6.5.10`, and `org.springframework:spring-web` from `6.0.12` to `6.2.18`.
- Updated `org.springframework.security:spring-security-ldap` in `kerb4j-server-spring-security-ldap` from `6.5.10` to `7.0.5`.
- Updated `org.hamcrest:hamcrest-library` from `2.2` to `3.0`.

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
