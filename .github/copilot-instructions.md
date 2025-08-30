# Kerb4J - Kerberos/SPNEGO Authentication Library

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

Kerb4J is an industry-standard Java library for working with Kerberos/SPNEGO authentication. It provides efficient client and server-side authentication with ticket caching, group membership extraction, and flexible SPN resolution.

## Working Effectively

### Build and Test Requirements
- **Java Version**: Requires Java 17 or higher (version 0.2.x+). Java 7+ supported for version 0.1.x
- **Build System**: Maven-based multi-module project
- **NEVER CANCEL BUILDS OR TESTS**: Set timeouts to 120+ minutes for full builds, 60+ minutes for tests

### Essential Commands (VALIDATED)
Run these commands from the repository root (`/path/to/kerb4j`):

1. **Clean and compile** (takes ~9 seconds):
   ```bash
   mvn clean compile -q
   ```

2. **Full build with tests** (takes ~48 seconds - NEVER CANCEL):
   ```bash
   mvn clean package -q
   ```
   - Set timeout to 120+ minutes in automation
   - Tests include real Kerberos server startup and authentication scenarios
   - Integration tests with Spring Boot and Tomcat

3. **Run tests only** (takes ~24 seconds - NEVER CANCEL):
   ```bash
   mvn test -q
   ```
   - Set timeout to 60+ minutes in automation
   - Tests start multiple KDC (Key Distribution Center) servers
   - Validates end-to-end Kerberos authentication flows

4. **Install without tests** (takes ~28 seconds):
   ```bash
   mvn clean install -DskipTests -q
   ```

### Project Structure
```
kerb4j/                          # Root multi-module Maven project
├── kerb4j-base64/              # Base64 encoding utilities
│   ├── kerb4j-base64-common/   # Common Base64 functionality
│   └── kerb4j-base64-java8/    # Java 8 specific implementations
├── kerb4j-common/              # Core Kerberos functionality and test infrastructure
├── kerb4j-client/              # Client-side SPNEGO/Kerberos authentication
└── kerb4j-server/              # Server-side authentication modules
    ├── kerb4j-server-common/       # Shared server components
    ├── kerb4j-server-tomcat/       # Apache Tomcat integration
    ├── kerb4j-server-spring-security/      # Spring Security integration
    └── kerb4j-server-spring-security-ldap/ # Spring Security LDAP integration
```

## Validation Scenarios

### Manual Testing Requirements
After making changes, ALWAYS validate functionality by running complete scenarios:

1. **Basic Build Validation**:
   ```bash
   mvn clean compile -q && echo "Build successful"
   ```

2. **Authentication Flow Testing**:
   ```bash
   # Run specific module tests to validate authentication
   cd kerb4j-common && mvn test -Dtest=TestSimpleKdc -q
   ```
   - This starts a mini KDC server and validates Kerberos ticket generation
   - Confirms keytab creation and principal authentication

3. **Integration Testing**:
   ```bash
   mvn test -q
   ```
   - Validates Spring Boot integration with embedded Tomcat
   - Tests HTTP authentication flows with real Kerberos tokens
   - Confirms SPNEGO negotiation processes

### Key Test Scenarios
The test suite validates:
- **Kerberos ticket lifecycle**: TGT acquisition, service ticket generation, caching
- **SPNEGO negotiation**: HTTP header creation and validation
- **Spring Security integration**: Authentication provider and filter functionality
- **Tomcat integration**: Valve-based authentication in servlet containers
- **Group extraction**: Microsoft AD PAC (Privilege Attribute Certificate) parsing

## CI/CD Integration

### GitHub Actions
The project includes CI workflows (`.github/workflows/maven.yml`):
- Tests on Java 17, 18, 19, 20, 21
- Runs on Ubuntu, Windows, and macOS
- Uses: `mvn -B clean package --file pom.xml -U`

### Build Artifacts
- JARs are generated in each module's `target/` directory
- Javadoc artifacts included via `maven-javadoc-plugin`
- Source artifacts via `maven-source-plugin`

## Development Guidelines

### Common Development Tasks

1. **Run specific module tests**:
   ```bash
   cd kerb4j-[module-name]
   mvn test -q
   ```

2. **Check module dependencies**:
   ```bash
   mvn dependency:tree | head -30
   ```

3. **Work with integration tests**: 
   - Tests automatically start embedded KDC servers on dynamic ports
   - Use `KerberosSecurityTestcase` as base class for Kerberos-related tests
   - Integration tests include Spring Boot web applications with embedded Tomcat

### Key Classes and Concepts

**Client Side**:
- `SpnegoClient`: Main entry point for Kerberos authentication
- `SpnegoContext`: Handles security headers and mutual authentication
- `SpnegoHttpURLConnection`: HTTP client with automatic SPNEGO handling

**Server Side**:
- `SpnegoAuthenticationProvider`: Spring Security authentication provider
- `SpnegoAuthenticator`: Tomcat valve for servlet-based authentication
- `KerberosTicketValidator`: Interface for ticket validation

**Test Infrastructure**:
- `KerberosSecurityTestcase`: Base test class with mini KDC setup
- `SimpleKdcServer`: Embedded Kerberos server for testing

### Important Notes

1. **Thread Safety**: `SpnegoClient` instances are thread-safe and should be reused
2. **Ticket Caching**: TGT and service tickets are automatically cached and renewed
3. **SPN Resolution**: Flexible SPN specification without DNS lookups required
4. **Group Membership**: Extract user groups directly from Kerberos tokens (AD-specific)

## Troubleshooting

### Common Issues
- **Build timeouts**: Always use long timeouts (120+ minutes) for full builds
- **Port conflicts**: Tests use dynamic ports starting from 10000
- **Java version**: Ensure Java 17+ for current version (0.2.x)

### When Tests Fail
- Check for port conflicts if KDC startup fails
- Verify Java version compatibility
- Ensure sufficient test timeout values
- Review KDC server logs in test output for authentication errors

## Time Expectations (CRITICAL - NEVER CANCEL)

- **Compilation**: ~9 seconds
- **Full build with tests**: ~48 seconds (SET TIMEOUT: 120+ minutes)
- **Tests only**: ~24 seconds (SET TIMEOUT: 60+ minutes)  
- **Install without tests**: ~28 seconds

Always wait for completion - builds may vary based on system performance and network conditions.