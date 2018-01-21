Kerb4J
========

Industry standard library for working with Kerberos/SPNEGO authentication in Java in 2018.

Main features:
 - Getting group membership information from Kerberos token - no need to query LDAP
 - Proper caching of tickets - make just one request to domain controller and cache the ticket
 - Flexible SPN resolution - you own the code and do not have to rely on magic SPN calculation algorithms
 
Installation
========

Kerb4J is available from Maven Central repo:

**Client**
```xml
<dependency>
    <groupId>com.kerb4j</groupId>
    <artifactId>kerb4j-client</artifactId>
    <version>0.0.5</version>
</dependency>
```

**Spring Security**
```xml
<dependency>
    <groupId>com.kerb4j</groupId>
    <artifactId>kerb4j-server-spring-security</artifactId>
    <version>0.0.5</version>
</dependency>
```

**Tomcat**
```xml
<dependency>
    <groupId>com.kerb4j</groupId>
    <artifactId>kerb4j-server-tomcat</artifactId>
    <version>0.0.5</version>
</dependency>
```

SPNEGO/Kerberos Client
========

Kerb4J provides efficient way to create Kerberos/SPNEGO HTTP Clients. Main two classes you'll need are `SpnegoClient` and `SpnegoContext`
- `SpnegoClient` provides API for authenticating client in KDC (e.g. in Active Directory Domain Controller).
- `SpnegoContext` is responsible for accessing downstream systems, creating and validating appropriate security HTTP headers.

`SpnegoClient` supports authentication using name and password, keytab file or ticket cache.

Example usage:
```java
SpnegoClient spnegoClient = SpnegoClient.loginWithKeyTab("svc_consumer", "/opt/myapp/consumer.keytab");
```

`SpnegoContext` allows creating 'Authorization: Negotiate XXXXX' header and optionally validating `WWW-Authenticate` response header for SPNEGO mutual authentication

Example usage:
```java
URL url = new URL("http://api.provider.acme.com/api/operation1");
SpnegoContext context = spnegoClient.createContext("http://provider.acme.com"); // Will result in HTTP/provider.acme.com SPN
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
conn.setRequestProperty("Authorization", context.createTokenAsAuthroizationHeader());
```