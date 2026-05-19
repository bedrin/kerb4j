# Changelog

All notable changes to this project are documented in this file.

## 0.2.2

### Release preparation
- Finalized all module versions to `0.2.2` for release publishing.

### Dependencies
- Updated `org.springframework.security:spring-security-ldap` in `kerb4j-server-spring-security-ldap` from `6.1.5` to `7.0.5`.
- Updated `org.hamcrest:hamcrest-library` from `2.2` to `3.0`.
- No other direct Spring dependency versions changed for `0.2.2`; the shared Spring Boot and Spring Security versions remained at `3.1.4` and `6.1.5`.

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
