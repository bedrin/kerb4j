# Changelog

All notable changes to this project are documented in this file.

## 0.4.0-SNAPSHOT

### New Functionality
- Added pluggable `SpnegoClient` implementations with classpath-based provider selection. `kerb4j-client-kerby` is preferred when present; otherwise `kerb4j-client-jdk` provides the existing JDK JAAS/JGSS behavior.
- Added Apache Kerby-backed client ticket acquisition for username/password logins and service-ticket-backed Negotiate header creation.
- Reactive Spring Security support via `[kerb4j-server-spring-webflux](kerb4j-server/kerb4j-server-spring-webflux)` module
- Multi-principal SPNEGO support is now shared in `kerb4j-server-spring-security-core` for feature parity between servlet and reactive Spring stacks
- Multi-principal fallback policy is now owned by `MultiPrincipalManager` (including explicit default principal support) so servlet Spring and Tomcat authenticator paths delegate principal resolution consistently

### Bug fixes
- Fixed PAC resource-domain group SID expansion in `PacLogonInfo`:
- MS-PAC KERB_VALIDATION_INFO: `ResourceGroupDomainSid` + `ResourceGroupIds` create resource group SIDs.
- MS-KILE Domain Local Group Membership: compressed resource SIDs are represented as `GROUP_MEMBERSHIP` RelativeIds under `ResourceGroupDomainSid`.
- Resource group SIDs are now built once and no longer have `ResourceGroupDomainSid` appended twice.

### Breaking change note
- `PacLogonInfo#getResourceGroupSids()` now returns correctly constructed resource group SIDs without duplicated domain components. Code that previously relied on the incorrect double-appended SID format may need adjustment.

## 0.3.0

### Release preparation
- Finalized all module versions to `0.3.0` for release publishing.

### Dependencies
- Updated `org.springframework.boot` from `3.5.14` to `4.0.6`.

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
