Kerb4J
========
![Java CI](https://github.com/bedrin/kerb4j/workflows/Java%20CI/badge.svg?branch=develop)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.kerb4j/kerb4j/badge.svg?style=flat)](https://maven-badges.herokuapp.com/maven-central/com.kerb4j/kerb4j)

Industry standard library for working with Kerberos/SPNEGO authentication in Java in 2023+.

Main features:

- Getting group membership information from Kerberos token - no need to query LDAP
- Proper caching of tickets - make just one request to domain controller and cache the ticket on both client and server
  sides
- Flexible SPN resolution - you own the code and do not have to rely on magic SPN calculation algorithms
- **NEW**: Pluggable Kerberos implementations - choose between JDK GSS API and Apache Kerby

## Kerberos Implementation Support

Kerb4J now supports multiple Kerberos implementations through a pluggable integration layer:

- **JDK Implementation**: Uses built-in JDK GSS API (default, mature)
- **Apache Kerby**: Pure Java implementation, cross-platform

See [Integration Layer Documentation](kerb4j-integration/README.md) for details.

Java Compatibility
========
Version 0.2.x+ requires Java 17 or higher
Version 0.1.x+ supports Java 7+

Installation
========

Kerb4J is available from Maven Central repo:

**Client**

```xml
<dependency>
    <groupId>com.kerb4j</groupId>
    <artifactId>kerb4j-client</artifactId>
    <version>0.2.0</version>
</dependency>
```

**Spring Security**

```xml
<dependency>
    <groupId>com.kerb4j</groupId>
    <artifactId>kerb4j-server-spring-security</artifactId>
    <version>0.2.0</version>
</dependency>
```

**Tomcat**

```xml
<dependency>
    <groupId>com.kerb4j</groupId>
    <artifactId>kerb4j-server-tomcat</artifactId>
    <version>0.2.0</version>
</dependency>
```

SPNEGO/Kerberos Client
========

Kerb4J provides efficient way to create Kerberos/SPNEGO HTTP Clients. Main two classes you'll need are `SpnegoClient`
and `SpnegoContext`

- `SpnegoClient` provides API for authenticating client in KDC (e.g. in Active Directory Domain Controller).
- `SpnegoContext` is responsible for accessing downstream systems, creating and validating appropriate security HTTP
  headers.

`SpnegoClient` supports authentication using name and password, keytab file or ticket cache.

Example usage:

```java
SpnegoClient spnegoClient = SpnegoClient.loginWithKeyTab("svc_consumer", "/opt/myapp/consumer.keytab");
```

`SpnegoContext` allows creating 'Authorization: Negotiate XXXXX' header and optionally validating `WWW-Authenticate`
response header for SPNEGO mutual authentication

Example usage:

```java
URL url = new URL("http://api.provider.acme.com/api/operation1");
SpnegoContext context = spnegoClient.createContext("http://provider.acme.com"); // Will result in HTTP/provider.acme.com SPN
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
conn.setRequestProperty("Authorization", context.createTokenAsAuthroizationHeader());
```

**SPN resolution**

Kerb4J allows you to specify SPN for the downstream system manually without doing any reverse DNS lookups,
canonicalizations, e.t.c. You can even use SPN `HTTP/foo` for calling service `bar`

**Caching tickets**

Consider you want to make a million of HTTP requests to Kerberos-protected server. Kerb4J will allow you to make just
two requests to the KDC (e.g. in Active Directory Domain Controller).

One `SpnegoClient` is created, Kerb4J will make first request for TGT (authentication). TGT will be cached and renewed
only when tickets expired. Reuse the `SpnegoClient` instance for all requests you want to make using the same
credentials.

When you create first `SpnegoContext` instance for the given SPN, Kerb4J will make another request for a service ticket.
This service ticket will be reused when creating new `SpnegoContext` instances from the same `SpnegoClient`.

So the rule of thumb - reuse the same `SpnegoClient` instance (it is threadsafe by the way), create new `SpnegoContext`
instance for each request.


SPNEGO/Kerberos Server
========

Validating Kerberos/SPNEGO tickets on server side is even simpler than client side.

Use `SpnegoClient` and authenticate in KDC (e.g. in Active Directory Domain Controller) using your server account.
Call `spnegoClient.createAcceptContext()` method to create a `SpnegoContext` instance responsible for authenticating
your client. Pass decoded SPNEGO token (Base64 decoded value of token in 'Authorization: Negotiate' header)
to `spnegoContext.acceptToken` method to validate it.

If you only plan to validate client tokens on your server and do not use credentials delegation or reusing the same `SpnegoClient` for accessing other servers, you can create "offline" `SpengoClient` by passing `acceptOnly = true` parameter to `SpengoClient.loginWithKeyTab` factory method.

Please note that it works with `keytab` secrets only.

Kerb4J comes with an Authenticator for Apache Tomcat (kerb4j-server-tomcat artifact) as well as authentication provider
for Spring Security (See kerb4j-server-spring-security)

**Extracting groups from Kerberos ticket generated by Active Directory**

Spnego allows you to extract user groups from SPNEGO token (one sent from client to server) without making any
additional requests to Active Directory.

```java
String negotiateHeaderValue = request.getHeader("Authorization").substring(10);
byte[] decoded = Base64.decodeBase64(negotiateHeaderValue);
SpnegoInitToken spnegoInitToken = new SpnegoInitToken(decoded);
SpnegoKerberosMechToken spnegoKerberosMechToken = spnegoInitToken.getSpnegoKerberosMechToken();
Pac pac = spnegoKerberosMechToken.getPac(spnegoClient.getKerberosKeys());
PacLogonInfo logonInfo = pac.getLogonInfo();
List<String> roles = Stream.of(logonInfo.getGroupSids()).map(PacSid::toHumanReadableString).collect(Collectors.toList());
```

This functionality is specific to Microsoft Active Directory and supported both by Kerb4J Tomcat and Spring Security
integrations. 