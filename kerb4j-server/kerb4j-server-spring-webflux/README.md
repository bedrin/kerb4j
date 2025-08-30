# Spring WebFlux Support for Kerb4J

This module provides Spring WebFlux reactive support for Kerberos/SPNEGO authentication in kerb4j.

## Overview

The `kerb4j-server-spring-webflux` module extends kerb4j to support Spring WebFlux applications with reactive streams and non-blocking I/O. This module provides WebFlux equivalents of the Spring MVC components found in the `kerb4j-server-spring-security` module.

## Key Components

### SpnegoServerAuthenticationEntryPoint

Reactive equivalent of `SpnegoEntryPoint` that implements `ServerAuthenticationEntryPoint`. This component:

- Sends `WWW-Authenticate: Negotiate` header to initiate SPNEGO authentication
- Supports optional redirect URLs for fallback authentication (e.g., form login)
- Works with reactive ServerWebExchange instead of servlet request/response

### SpnegoServerAuthenticationConverter

Reactive authentication converter that implements `ServerAuthenticationConverter`. This component:

- Parses SPNEGO `Negotiate` headers from incoming requests
- Supports basic authentication fallback when configured
- Creates `SpnegoRequestToken` objects from Kerberos tickets
- Handles both SPNEGO and basic authentication headers

### ReactiveAuthenticationManagerAdapter

Adapter that wraps traditional `AuthenticationManager` implementations for use in reactive applications. This component:

- Adapts blocking authentication managers to reactive streams
- Uses bounded elastic scheduler for non-blocking operations
- Allows reuse of existing Kerberos authentication providers

### SpnegoWebFluxConfigurer

Utility class providing helper methods to configure SPNEGO authentication in WebFlux applications:

- `createSpnegoAuthenticationWebFilter()` - Creates configured authentication web filters
- Supports custom matchers and authentication managers
- Provides both blocking and reactive authentication manager support

## Usage

### Basic Configuration

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
                        .pathMatchers("/").permitAll()
                        .pathMatchers("/hello").hasRole("USER")
                        .anyExchange().permitAll())
                .addFilterBefore(spnegoAuthenticationWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    @Bean
    public AuthenticationWebFilter spnegoAuthenticationWebFilter() {
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

    // ... other beans
}
```

### With Form Login Fallback

```java
@Bean
public SpnegoServerAuthenticationEntryPoint spnegoServerAuthenticationEntryPoint() {
    return new SpnegoServerAuthenticationEntryPoint("/login");
}
```

### Custom Authentication Matching

```java
@Bean
public AuthenticationWebFilter spnegoAuthenticationWebFilter() {
    ServerWebExchangeMatcher matcher = ServerWebExchangeMatchers.pathMatchers("/secure/**");
    return SpnegoWebFluxConfigurer.createSpnegoAuthenticationWebFilter(
            new ReactiveAuthenticationManagerAdapter(authManager()),
            matcher,
            true // support basic auth fallback
    );
}
```

## Dependencies

This module depends on:

- `kerb4j-server-common` - Core server functionality
- `kerb4j-server-spring-security` - Reuses authentication providers and tokens
- `spring-boot-starter-webflux` - Spring WebFlux reactive web framework
- `spring-boot-starter-security` - Spring Security with reactive support
- `reactor-core` - Reactive streams implementation

## Integration with Existing Code

This module is designed to work alongside the existing `kerb4j-server-spring-security` module:

- **Reuses**: Authentication providers, ticket validators, tokens, and user details services
- **Adds**: Reactive/WebFlux-specific filters, entry points, and configuration helpers
- **Maintains**: Full backward compatibility with existing WebMVC applications

## Testing

The module includes comprehensive tests for:

- `SpnegoServerAuthenticationEntryPoint` - Entry point behavior and configuration
- `SpnegoServerAuthenticationConverter` - Token parsing and conversion
- `ReactiveAuthenticationManagerAdapter` - Reactive wrapper functionality
- Integration scenarios with sample configurations

Run tests with:

```bash
mvn test
```

## Migration from WebMVC

To migrate from WebMVC to WebFlux:

1. Replace `@EnableWebSecurity` with `@EnableWebFluxSecurity`
2. Replace `SecurityFilterChain` with `SecurityWebFilterChain`
3. Replace `HttpSecurity` with `ServerHttpSecurity`
4. Use `SpnegoWebFluxConfigurer` instead of manual filter configuration
5. Wrap existing `AuthenticationManager` with `ReactiveAuthenticationManagerAdapter`

The authentication providers, ticket validators, and business logic remain unchanged.