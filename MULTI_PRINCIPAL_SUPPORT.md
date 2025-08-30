# Multi-Principal SPNEGO Support

This document describes the multi-principal support feature added to kerb4j, which allows a single server to handle SPNEGO authentication for multiple service principal names (SPNs).

## Overview

Previously, kerb4j only supported a single Kerberos principal per server. This limitation meant that servers with multiple DNS aliases or services couldn't handle SPNEGO tokens for different SPNs without separate configurations.

The multi-principal support feature allows a server to:
- Handle SPNEGO tokens for multiple service principals (e.g., `HTTP/www1.server.com@REALM` and `HTTP/www2.server.com@REALM`)
- Automatically extract the target SPN from incoming SPNEGO tokens
- Select the appropriate principal/keytab based on the target SPN
- Maintain full backward compatibility with existing single-principal configurations

## How It Works

1. When a SPNEGO token is received, the library extracts the target service principal name from the unencrypted part of the Kerberos ticket
2. The multi-principal manager looks up the appropriate `SpnegoClient` for that SPN
3. The selected `SpnegoClient` is used to validate the token
4. If no specific principal is found, the system can fall back to a default principal (if configured)

## Usage Examples

### Spring Security Configuration

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

#### Multi-Principal Configuration
```java
@Bean
public SimpleMultiPrincipalManager multiPrincipalManager() {
    SimpleMultiPrincipalManager manager = new SimpleMultiPrincipalManager();
    
    // Add multiple principals with their respective keytabs
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
    return validator;
}
```

#### Hybrid Configuration (Multi-Principal with Fallback)
```java
@Bean
public SunJaasKerberosTicketValidator kerberosTicketValidator() {
    SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
    
    // Configure multi-principal support
    validator.setMultiPrincipalManager(multiPrincipalManager());
    
    // Also configure a default principal as fallback
    validator.setServicePrincipal("HTTP/default.server.com@EXAMPLE.COM");
    validator.setKeyTabLocation(new FileSystemResource("/etc/keytabs/default.keytab"));
    
    return validator;
}
```

### Tomcat Configuration

#### Multi-Principal Tomcat Authenticator
```java
// In your Tomcat context configuration
TomcatMultiPrincipalManager multiPrincipalManager = new TomcatMultiPrincipalManager();
multiPrincipalManager.addPrincipal("HTTP/www1.server.com@EXAMPLE.COM", "/etc/keytabs/www1.keytab");
multiPrincipalManager.addPrincipal("HTTP/www2.server.com@EXAMPLE.COM", "/etc/keytabs/www2.keytab");

SpnegoAuthenticator authenticator = new SpnegoAuthenticator();
authenticator.setMultiPrincipalManager(multiPrincipalManager);
```

#### XML Configuration for Tomcat
```xml
<Context>
    <Valve className="com.kerb4j.server.tomcat.SpnegoAuthenticator"
           multiPrincipalManager="#{multiPrincipalManager}" />
</Context>
```

## Migration Guide

### From Single Principal to Multi-Principal

1. **Identify your current configuration**: Find where you set `servicePrincipal` and `keyTabLocation`
2. **Create a multi-principal manager**: Instantiate `SimpleMultiPrincipalManager` (Spring) or `TomcatMultiPrincipalManager` (Tomcat)
3. **Add your principals**: Use `addPrincipal()` to configure each SPN with its keytab
4. **Update the validator**: Set the multi-principal manager instead of individual principal properties
5. **Test**: Verify that all your services still work correctly

### Backward Compatibility

The changes are fully backward compatible. Existing configurations will continue to work without any modifications. You only need to update your configuration if you want to take advantage of multi-principal support.

## API Reference

### Core Classes

#### `MultiPrincipalManager` (Interface)
- `SpnegoClient getSpnegoClientForSPN(String spn)`: Get client for specific SPN
- `boolean hasPrincipalForSPN(String spn)`: Check if SPN is configured
- `String[] getConfiguredSPNs()`: Get all configured SPNs

#### `SimpleMultiPrincipalManager` (Spring Security)
- `void addPrincipal(String principal, Resource keyTabLocation)`: Add a principal with keytab
- `void addPrincipal(String principal, Resource keyTabLocation, boolean acceptOnly)`: Add with accept-only option

#### `TomcatMultiPrincipalManager` (Tomcat)
- `void addPrincipal(String principal, String keyTabLocation)`: Add a principal with keytab path

### Enhanced Classes

#### `SunJaasKerberosTicketValidator`
- `void setMultiPrincipalManager(MultiPrincipalManager manager)`: Enable multi-principal mode

#### `SpnegoAuthenticator` (Tomcat)
- `void setMultiPrincipalManager(TomcatMultiPrincipalManager manager)`: Enable multi-principal mode

#### `SpnegoInitToken`
- `String getServerPrincipalName()`: Extract target SPN from token

#### `SpnegoKerberosMechToken`
- `String getServerPrincipalName()`: Extract target SPN from ticket

## Troubleshooting

### Common Issues

1. **"No principal configured for SPN"**: Ensure the SPN in the token matches exactly what you configured
2. **Keytab errors**: Verify keytab files exist and contain the correct principals
3. **Permission errors**: Ensure the application has read access to keytab files
4. **Principal name mismatches**: SPNs are case-sensitive and must match exactly

### Debugging

Enable debug logging to see which SPN is extracted and which principal is selected:
```properties
logging.level.com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator=DEBUG
logging.level.com.kerb4j.server.tomcat.SpnegoAuthenticator=DEBUG
```

### Testing

Use the `klist` command to verify your keytab contents:
```bash
klist -kt /etc/keytabs/www1.keytab
```

## Performance Considerations

- Principal lookup is O(1) using hash maps
- No performance impact for single-principal configurations
- Minimal overhead for SPN extraction from tokens
- Consider using accept-only mode (`acceptOnly=true`) for server-side principals to avoid unnecessary KDC communication

## Security Considerations

- Store keytab files securely with appropriate file permissions (600 or 640)
- Keep keytab files outside the application classpath
- Regularly rotate service account passwords and update keytabs
- Monitor for authentication failures that might indicate misconfiguration or attacks