# Multi-Principal SPNEGO Support

This document describes the multi-principal support feature added to kerb4j, which allows a
single server to handle SPNEGO authentication for multiple service principal names (SPNs).

## Overview

Previously, kerb4j only supported a single Kerberos principal per server. This limitation
meant that servers with multiple DNS aliases or services couldn't handle SPNEGO tokens for
different SPNs without separate configurations.

The multi-principal support feature allows a server to:
- Handle SPNEGO tokens for multiple service principals (e.g., `HTTP/www1.server.com@REALM`
  and `HTTP/www2.server.com@REALM`)
- Automatically extract the target SPN from the unencrypted metadata of incoming SPNEGO tokens
- Select the appropriate principal/keytab based on the target SPN
- Optionally fall back to a configured default principal when the token SPN is unknown

## Supported Modes

### Single-Principal Mode (existing behavior, unchanged)

Configure `servicePrincipal` and `keyTabLocation` (or `servicePassword`) on the validator.
Multi-principal selection is not performed.

### Pure Multi-Principal Mode

Configure only a `MultiPrincipalManager` with at least one SPN. Tokens targeting an unknown
or unextractable SPN are **rejected** with `BadCredentialsException` / HTTP 401.  There is no
implicit fallback to a broader principal.

### Hybrid Mode (multi-principal with default fallback)

Configure a `MultiPrincipalManager` with explicit fallback/default principal. When a token arrives:
1. If the token SPN matches a configured SPN in the manager → the matching client is used.
2. If the token SPN is unknown or unextractable **and** a fallback principal is configured in the manager →
   the default principal is used as a fallback.
3. If the token SPN is unknown or unextractable and there is **no** fallback principal →
   the request is rejected.

⚠ Use hybrid mode deliberately. Falling back to a default principal means that a broad
service account may validate tokens that were intended for a specific SPN.

## How SPN Extraction Works

When a SPNEGO token is received, `SpnegoInitToken.getServerPrincipalName()` extracts the
target service principal from the unencrypted metadata of the Kerberos ticket (the ticket's
`sname` and realm fields, which are outside the encrypted `EncTicketPart`). The returned
string is in canonical form: `service/host@REALM`, e.g. `HTTP/www.example.com@EXAMPLE.COM`.

SPN matching is **exact and case-sensitive**. The string used as the map key in your
`MultiPrincipalManager` must match this canonical form precisely.

## Usage Examples

### Spring Security (Servlet / WebMVC)

```java
import com.kerb4j.server.MultiPrincipalManager;
import com.kerb4j.server.spring.SimpleMultiPrincipalManager;
import com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator;
```

#### Single Principal (Backward Compatible)
```java
@Bean
public SunJaasKerberosTicketValidator kerberosTicketValidator() {
    SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
    validator.setServicePrincipal("HTTP/server.example.com@EXAMPLE.COM");
    validator.setKeyTabLocation(new FileSystemResource("/etc/keytabs/server.keytab"));
    return validator;
}
```

#### Pure Multi-Principal Configuration
```java
@Bean
public SimpleMultiPrincipalManager multiPrincipalManager() {
    SimpleMultiPrincipalManager manager = new SimpleMultiPrincipalManager();
    // SPNs must be exact canonical strings including realm (case-sensitive).
    // Keytab resources must resolve to local files; classpath resources inside JARs are not supported.
    manager.addPrincipal("HTTP/www1.server.com@EXAMPLE.COM",
                         new FileSystemResource("/etc/keytabs/www1.keytab"));
    manager.addPrincipal("HTTP/www2.server.com@EXAMPLE.COM",
                         new FileSystemResource("/etc/keytabs/www2.keytab"));
    manager.addPrincipal("HTTP/api.server.com@EXAMPLE.COM",
                         new FileSystemResource("/etc/keytabs/api.keytab"));
    return manager;
}

@Bean
public SunJaasKerberosTicketValidator kerberosTicketValidator() {
    SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
    validator.setMultiPrincipalManager(multiPrincipalManager());
    // Tokens for unknown SPNs are rejected (no fallback).
    return validator;
}
```

#### Hybrid Configuration (Multi-Principal with Default Fallback)
```java
@Bean
public SimpleMultiPrincipalManager multiPrincipalManager() {
    SimpleMultiPrincipalManager manager = new SimpleMultiPrincipalManager();
    manager.addPrincipal("HTTP/www1.server.com@EXAMPLE.COM",
                         new FileSystemResource("/etc/keytabs/www1.keytab"));
    manager.addPrincipal("HTTP/www2.server.com@EXAMPLE.COM",
                         new FileSystemResource("/etc/keytabs/www2.keytab"));
    manager.addDefaultPrincipal("HTTP/default.server.com@EXAMPLE.COM",
                                new FileSystemResource("/etc/keytabs/default.keytab"));
    return manager;
}

@Bean
public SunJaasKerberosTicketValidator kerberosTicketValidator() {
    SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
    validator.setMultiPrincipalManager(multiPrincipalManager());
    return validator;
}
```

### Spring WebFlux Configuration

The same `SunJaasKerberosTicketValidator` and `SimpleMultiPrincipalManager` classes from
`kerb4j-server-spring-security-core` are used for both servlet and reactive stacks:

```java
import com.kerb4j.server.spring.SimpleMultiPrincipalManager;
import com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator;

@Bean
public SimpleMultiPrincipalManager multiPrincipalManager() {
    SimpleMultiPrincipalManager manager = new SimpleMultiPrincipalManager();
    manager.addPrincipal("HTTP/www1.server.com@EXAMPLE.COM",
                         new FileSystemResource("/etc/keytabs/www1.keytab"));
    manager.addPrincipal("HTTP/www2.server.com@EXAMPLE.COM",
                         new FileSystemResource("/etc/keytabs/www2.keytab"));
    return manager;
}

@Bean
public SunJaasKerberosTicketValidator kerberosTicketValidator() {
    SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
    validator.setMultiPrincipalManager(multiPrincipalManager());
    return validator;
}
```

See `kerb4j-server-spring-webflux/README.md` for the full reactive filter-chain setup.

### Tomcat Configuration

Use `TomcatMultiPrincipalManager` (Tomcat-specific) and configure it programmatically.
Standard Tomcat XML (`<Valve>`) only supports simple string properties; Spring-style bean
references (`#{bean}`) are **not** available in plain Tomcat XML configuration.

```java
import com.kerb4j.server.tomcat.TomcatMultiPrincipalManager;
import com.kerb4j.server.tomcat.SpnegoAuthenticator;

TomcatMultiPrincipalManager multiPrincipalManager = new TomcatMultiPrincipalManager();
// Keytab locations must be absolute paths to local files.
multiPrincipalManager.addPrincipal("HTTP/www1.server.com@EXAMPLE.COM", "/etc/keytabs/www1.keytab");
multiPrincipalManager.addPrincipal("HTTP/www2.server.com@EXAMPLE.COM", "/etc/keytabs/www2.keytab");

SpnegoAuthenticator authenticator = new SpnegoAuthenticator();
authenticator.setMultiPrincipalManager(multiPrincipalManager);
// Optionally set explicit fallback:
// multiPrincipalManager.addDefaultPrincipal("HTTP/default@EXAMPLE.COM", "/etc/keytabs/default.keytab");
```

## API Reference

### `MultiPrincipalManager` (Interface — `com.kerb4j.server`)
- `SpnegoClient getSpnegoClientForSpn(String spn)` — Get the client for a specific SPN;
  returns `null` if not configured and fallback is disabled
- `boolean hasPrincipalForSpn(String spn)` — Check if an SPN is configured
- `Collection<String> getConfiguredSpns()` — Get all configured exact-match SPNs; never `null`
- `SpnegoClient getDefaultSpnegoClient()` — Get explicit fallback client, if configured

### `SimpleMultiPrincipalManager` (`com.kerb4j.server.spring` in `kerb4j-server-spring-security-core`)
- `void addPrincipal(String principal, Resource keyTabLocation)` — Add a principal; keytab
  must be a local file resource
- `void addPrincipal(String principal, Resource keyTabLocation, boolean acceptOnly)` — Add
  with explicit accept-only flag
- `void addDefaultPrincipal(String principal, Resource keyTabLocation)` — Configure fallback principal
- `void addDefaultPrincipal(String principal, Resource keyTabLocation, boolean acceptOnly)` — Configure fallback principal with explicit accept-only flag

### `TomcatMultiPrincipalManager` (`com.kerb4j.server.tomcat`)
- `void addPrincipal(String principal, String keyTabLocation)` — Add a principal by keytab path
- `void addDefaultPrincipal(String principal, String keyTabLocation)` — Configure fallback principal

### `SunJaasKerberosTicketValidator` (`com.kerb4j.server.spring.jaas.sun`)
- `void setMultiPrincipalManager(MultiPrincipalManager manager)` — Enable multi-principal mode

### `SpnegoInitToken` / `SpnegoKerberosMechToken` (`com.kerb4j.server.marshall.spnego`)
- `String getServerPrincipalName()` — Extract the canonical target SPN from token metadata

## Migration Guide

### From Single Principal to Multi-Principal

1. **Identify** your current `servicePrincipal` and `keyTabLocation` settings
2. **Create** a `SimpleMultiPrincipalManager` (Spring) or `TomcatMultiPrincipalManager` (Tomcat)
3. **Add** each SPN with its keytab using `addPrincipal()`; use the exact canonical SPN string
   including realm (e.g. `HTTP/host.example.com@EXAMPLE.COM`)
4. **Set** the multi-principal manager on the validator/authenticator
5. **Configure fallback on the manager** with `addDefaultPrincipal(...)` only if needed
6. **Test** with `klist -kt /path/to.keytab` to verify keytab principal names match exactly

### Backward Compatibility

Existing single-principal configurations continue to work without modification.

## Limitations

- Keytab resources must resolve to **local files**. Classpath resources embedded inside JAR
  files are not supported by `SimpleMultiPrincipalManager` (an `IllegalArgumentException` is
  thrown at configuration time).
- SPN matching is exact and case-sensitive. The SPN string extracted from the token must
  exactly match the key used in `addPrincipal()`.
- Standard Tomcat XML `<Valve>` configuration only supports simple string properties; bean
  references require a custom Tomcat lifecycle listener or Spring-embedded Tomcat.

## Troubleshooting

### Common Issues

1. **"No principal configured for SPN: ..."** — The SPN in the token does not match any
   configured principal. Check with `klist -kt` that the keytab contains the right SPN and
   that the format (including realm) is identical.
2. **Keytab errors** — Verify keytab files exist, are readable, and contain the correct
   principal entries.
3. **IllegalArgumentException on non-file resource** — Classpath resources inside JARs cannot
   be resolved to a local file path. Use `FileSystemResource` with an absolute path instead.

### Debugging

Enable DEBUG logging to see which SPN is extracted and which principal is selected:
```properties
logging.level.com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator=DEBUG
logging.level.com.kerb4j.server.tomcat.SpnegoAuthenticator=DEBUG
```

### Verifying Keytab Contents

```bash
klist -kt /etc/keytabs/www1.keytab
```

The output shows exactly which principal names are in the keytab. These must match what you
pass to `addPrincipal()`.

## Security Considerations

- Store keytab files securely with appropriate file permissions (600 or 640)
- Keep keytab files outside the application classpath
- In pure multi-principal mode the server fails closed (401) for unknown SPNs
- In hybrid mode the manager fallback principal acts as a catch-all; consider whether that is appropriate
  for your threat model
- Monitor authentication failures that might indicate misconfiguration or probing
