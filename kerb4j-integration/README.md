# Kerberos Integration Layer

Kerb4J now supports multiple Kerberos implementations through a pluggable integration layer. This allows you to choose between different Kerberos backends based on your needs.

## Available Implementations

### JDK Implementation (kerb4j-integration-jdk)
- Uses the built-in JDK GSS API
- Mature and battle-tested
- Directly compatible with existing Kerb4J code
- Requires Oracle/OpenJDK (Sun) JVM for full functionality

### Apache Kerby Implementation (kerb4j-integration-kerby)
- Uses Apache Kerby library
- Pure Java implementation
- Cross-platform and JVM-independent
- Still in development - basic functionality implemented

## Usage

### Adding Dependencies

To use the integration layer, add the API module and one or more implementation modules:

```xml
<!-- Core integration API -->
<dependency>
    <groupId>com.kerb4j</groupId>
    <artifactId>kerb4j-integration-api</artifactId>
    <version>0.2.0</version>
</dependency>

<!-- JDK implementation -->
<dependency>
    <groupId>com.kerb4j</groupId>
    <artifactId>kerb4j-integration-jdk</artifactId>
    <version>0.2.0</version>
</dependency>

<!-- Apache Kerby implementation -->
<dependency>
    <groupId>com.kerb4j</groupId>
    <artifactId>kerb4j-integration-kerby</artifactId>
    <version>0.2.0</version>
</dependency>
```

### Using the Integration Layer

#### Basic Usage (Default Implementation)

```java
import com.kerb4j.integration.api.KerberosClientProvider;
import com.kerb4j.integration.api.KerberosClientFactory;
import com.kerb4j.integration.api.KerberosClient;

// Get the default factory (first implementation found on classpath)
KerberosClientFactory factory = KerberosClientProvider.getDefaultFactory();
KerberosClient client = factory.loginWithUsernamePassword("user", "password");
```

#### Choosing a Specific Implementation

```java
// Use JDK implementation
KerberosClientFactory jdkFactory = KerberosClientProvider.getFactory("JDK");
KerberosClient jdkClient = jdkFactory.loginWithKeyTab("service/host", "/path/to/keytab");

// Use Apache Kerby implementation
KerberosClientFactory kerbyFactory = KerberosClientProvider.getFactory("Apache Kerby");
KerberosClient kerbyClient = kerbyFactory.loginWithTicketCache("user@REALM");
```

#### Using Contexts

```java
KerberosClient client = factory.loginWithUsernamePassword("user", "password");

// Create context for a specific URL
try (KerberosContext context = client.createContext(new URL("http://service.example.com"))) {
    String authHeader = context.createTokenAsAuthroizationHeader();
    // Use authHeader in HTTP request
}

// Create context for a specific SPN
try (KerberosContext context = client.createContextForSPN("HTTP/service.example.com")) {
    byte[] token = context.createToken();
    // Use token for authentication
}
```

### Backward Compatibility

The integration layer is designed to be fully backward compatible. Existing code using `SpnegoClient` will continue to work unchanged. You can optionally use the new integration-aware factory:

```java
import com.kerb4j.common.integration.SpnegoClientFactory;

// This will use integration layer if available, otherwise falls back to original implementation
SpnegoClient client = SpnegoClientFactory.loginWithUsernamePassword("user", "password");

// Check which implementation is being used
String implementation = SpnegoClientFactory.getCurrentImplementationName();
System.out.println("Using: " + implementation); // "JDK" or "Apache Kerby"
```

## Architecture

The integration layer uses the Service Provider Interface (SPI) pattern to discover available implementations at runtime. Each implementation provides:

1. **KerberosClientFactory**: Factory for creating client instances
2. **KerberosClient**: Main client interface for authentication operations
3. **KerberosContext**: Security context for token handling

### Class Hierarchy

```
KerberosClientProvider (SPI loader)
├── KerberosClientFactory (interface)
│   ├── JdkKerberosClientFactory (JDK implementation)
│   └── KerbyKerberosClientFactory (Apache Kerby implementation)
├── KerberosClient (interface)
│   ├── JdkKerberosClient (wraps SpnegoClient)
│   └── KerbyKerberosClient (pure Apache Kerby)
└── KerberosContext (interface)
    ├── JdkKerberosContext (wraps SpnegoContext)
    └── KerbyKerberosContext (pure Apache Kerby)
```

## Migration Guide

### From Existing Kerb4J Code

No changes are required for existing code. The integration layer is optional and provides additional flexibility.

### To Use Integration Layer

1. Add integration dependencies to your project
2. Replace direct `SpnegoClient` usage with `KerberosClientProvider` API
3. Optionally specify which implementation to use

### Example Migration

Before:
```java
SpnegoClient client = SpnegoClient.loginWithKeyTab("service/host", "/path/to/keytab");
SpnegoContext context = client.createContext(url);
String authHeader = context.createTokenAsAuthroizationHeader();
```

After:
```java
KerberosClientFactory factory = KerberosClientProvider.getDefaultFactory();
KerberosClient client = factory.loginWithKeyTab("service/host", "/path/to/keytab");
KerberosContext context = client.createContext(url);
String authHeader = context.createTokenAsAuthroizationHeader();
```

## Implementation Status

| Feature | JDK Implementation | Apache Kerby Implementation |
|---------|-------------------|------------------------------|
| Username/Password Login | ✅ Complete | 🚧 Basic |
| Keytab Login | ✅ Complete | 🚧 Basic |
| Ticket Cache Login | ✅ Complete | 🚧 Basic |
| Token Creation | ✅ Complete | 🚧 Basic |
| Token Validation | ✅ Complete | 🚧 Basic |
| Mutual Authentication | ✅ Complete | 🚧 Basic |
| Credential Delegation | ✅ Complete | ❌ Not implemented |

Note: Apache Kerby implementation is currently a proof-of-concept. Full implementation requires more work on the Apache Kerby integration.