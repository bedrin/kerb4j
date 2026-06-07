# Spring WebFlux Support for Kerb4J

This module provides Spring WebFlux reactive support for Kerberos/SPNEGO authentication in kerb4j.

## Module Structure

The WebFlux and WebMVC integrations share core Kerberos/Spring Security primitives through a
dedicated common module:

```
kerb4j-server-spring-security-core   ← shared tokens, providers, validators
    ↑                                    ↑
kerb4j-server-spring-security        kerb4j-server-spring-webflux
(servlet/WebMVC integration)         (reactive/WebFlux integration)
```

`SpnegoRequestToken`, `SpnegoAuthenticationProvider`, `SunJaasKerberosTicketValidator`, and
other authentication primitives live in `kerb4j-server-spring-security-core`, which both
sibling modules depend on.

## Key Components

### SpnegoServerAuthenticationEntryPoint

Reactive equivalent of `SpnegoEntryPoint` that implements `ServerAuthenticationEntryPoint`. This component:

- Sends `WWW-Authenticate: Negotiate` header to initiate SPNEGO authentication
- Supports optional redirect URL for fallback login pages (uses `303 See Other` for redirects)
- Works with reactive `ServerWebExchange` instead of servlet request/response

### SpnegoServerAuthenticationConverter

Reactive authentication converter that implements `ServerAuthenticationConverter`. This component:

- Parses `Authorization: Negotiate <token>` headers from incoming requests
- Converts malformed headers to `BadCredentialsException` rather than letting raw exceptions bubble up
- **Basic authentication fallback is disabled by default** — enable it explicitly when needed
- Creates `SpnegoRequestToken` objects from decoded Kerberos tickets

### ReactiveAuthenticationManagerAdapter

Adapter that wraps traditional blocking `AuthenticationManager` implementations for use in
reactive applications. This component:

- Offloads blocking authentication work (Kerberos ticket validation, JAAS calls) to the
  `boundedElastic` scheduler — **authentication is not fully non-blocking**; it runs on a
  thread-pool-backed scheduler designed for blocking I/O
- Allows reuse of existing `SpnegoAuthenticationProvider` and `KerberosAuthenticationProvider`
  without modification

### SpnegoWebFluxConfigurer

Utility class providing helper methods to configure SPNEGO authentication in WebFlux applications:

- `createSpnegoAuthenticationWebFilter()` — Creates configured `AuthenticationWebFilter` instances
- Defaults to SPNEGO-only authentication; pass `true` to enable basic auth fallback
- Supports custom exchange matchers

## Usage

### Basic Configuration (SPNEGO-only)

```java
@Configuration
@EnableWebFluxSecurity
public class WebFluxSecurityConfig {

    @Value("${serverPrincipal}")
    private String serverPrincipal;

    @Value("${serverKeytab}")
    private String serverKeytab;

    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
        return http
                .exceptionHandling(e -> e.authenticationEntryPoint(spnegoServerAuthenticationEntryPoint()))
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/public/**").permitAll()
                        .anyExchange().hasRole("USER"))
                .addFilterBefore(spnegoAuthenticationWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    @Bean
    public AuthenticationWebFilter spnegoAuthenticationWebFilter() {
        // Wraps the blocking Kerberos AuthenticationManager on boundedElastic scheduler
        return SpnegoWebFluxConfigurer.createSpnegoAuthenticationWebFilter(
                new ReactiveAuthenticationManagerAdapter(authManager()));
    }

    @Bean
    public AuthenticationManager authManager() {
        return new ProviderManager(kerberosServiceAuthenticationProvider());
    }

    @Bean
    public SpnegoServerAuthenticationEntryPoint spnegoServerAuthenticationEntryPoint() {
        return new SpnegoServerAuthenticationEntryPoint();
    }

    @Bean
    public SpnegoAuthenticationProvider kerberosServiceAuthenticationProvider() {
        SpnegoAuthenticationProvider provider = new SpnegoAuthenticationProvider();
        provider.setTicketValidator(sunJaasKerberosTicketValidator());
        provider.setUserDetailsService(userDetailsService());
        return provider;
    }

    @Bean
    public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
        SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
        ticketValidator.setServicePrincipal(serverPrincipal);
        ticketValidator.setKeyTabLocation(new FileSystemResource(serverKeytab));
        return ticketValidator;
    }

    // ... userDetailsService() and other beans
}
```

### With Form Login Fallback (redirect on unauthenticated)

```java
@Bean
public SpnegoServerAuthenticationEntryPoint spnegoServerAuthenticationEntryPoint() {
    // Responds with 303 See Other + Location header when SPNEGO challenge fails
    return new SpnegoServerAuthenticationEntryPoint("/login");
}
```

### Enabling Basic Authentication Fallback (opt-in)

```java
@Bean
public AuthenticationWebFilter spnegoAuthenticationWebFilter() {
    // Enable Basic auth fallback explicitly — disabled by default
    return SpnegoWebFluxConfigurer.createSpnegoAuthenticationWebFilter(
            new ReactiveAuthenticationManagerAdapter(authManager()),
            true /* supportBasicAuthentication */
    );
}
```

### Multi-Principal Configuration (Reactive)

```java
import com.kerb4j.server.spring.SimpleMultiPrincipalManager;
import com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator;

@Bean
public SimpleMultiPrincipalManager multiPrincipalManager() {
    SimpleMultiPrincipalManager manager = new SimpleMultiPrincipalManager();
    // SPNs must be in canonical form: service/host@REALM (case-sensitive, exact match).
    // Keytabs must be local files; classpath resources inside JARs are not supported.
    manager.addPrincipal("HTTP/www1.server.com@EXAMPLE.COM",
            "/etc/keytabs/www1.keytab");
    manager.addPrincipal("HTTP/www2.server.com@EXAMPLE.COM",
            "/etc/keytabs/www2.keytab");
    return manager;
}

@Bean
public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
    SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
    ticketValidator.setMultiPrincipalManager(multiPrincipalManager());
    // Pure multi-principal mode: tokens for unknown SPNs are rejected with 401.
    // To add fallback, configure manager.addDefaultPrincipal(...).
    return ticketValidator;
}
```

`SimpleMultiPrincipalManager` is provided by `kerb4j-server-spring-security-core`, so the same
configuration style works in Tomcat, servlet Spring Security, and reactive Spring Security.

### Custom Authentication Matching

```java
@Bean
public AuthenticationWebFilter spnegoAuthenticationWebFilter() {
    ServerWebExchangeMatcher matcher = ServerWebExchangeMatchers.pathMatchers("/secure/**");
    return SpnegoWebFluxConfigurer.createSpnegoAuthenticationWebFilter(
            new ReactiveAuthenticationManagerAdapter(authManager()),
            matcher,
            false // SPNEGO only, no basic auth fallback
    );
}
```

## Maven Dependency

```xml
<dependency>
    <groupId>com.kerb4j</groupId>
    <artifactId>kerb4j-server-spring-webflux</artifactId>
    <version>${kerb4j.version}</version>
</dependency>
```

This module depends on `kerb4j-server-spring-security-core` (shared authentication primitives),
Spring Security reactive/WebFlux artifacts, and Reactor Core. Dependency versions are managed
by the Spring Boot BOM.

## Migration from WebMVC

To migrate from WebMVC (`kerb4j-server-spring-security`) to WebFlux:

1. Replace `@EnableWebSecurity` with `@EnableWebFluxSecurity`
2. Replace `SecurityFilterChain` with `SecurityWebFilterChain`
3. Replace `HttpSecurity` with `ServerHttpSecurity`
4. Replace `SpnegoAuthenticationProcessingFilter` + `SpnegoEntryPoint` with
   `SpnegoWebFluxConfigurer.createSpnegoAuthenticationWebFilter()` + `SpnegoServerAuthenticationEntryPoint`
5. Wrap existing `AuthenticationManager` with `ReactiveAuthenticationManagerAdapter`

Authentication providers, ticket validators, and user detail services from
`kerb4j-server-spring-security-core` work unchanged in both WebMVC and WebFlux configurations.
