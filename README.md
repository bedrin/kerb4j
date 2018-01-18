Kerb4J
========

Industry standard library for working with Kerberos/SPNEGO authentication in Java in 2018.

Main features:
 - Getting group membership information from Kerberos token - no need to query LDAP
 - Proper caching of tickets - make just one request to domain controller and cache the ticket
 - Flexible SPN resolution - you own the code and do not have to rely on magic SPN calculation algorithms
 
Maven
========

**Client**
```xml
<dependency>
    <groupId>com.kerb4j</groupId>
    <artifactId>kerb4j-client</artifactId>
    <version>0.0.5-SNAPSHOT</version>
</dependency>
```

**Spring Security**
```xml
<dependency>
    <groupId>com.kerb4j</groupId>
    <artifactId>kerb4j-server-spring-security</artifactId>
    <version>0.0.5-SNAPSHOT</version>
</dependency>
```

**Tomcat**
```xml
<dependency>
    <groupId>com.kerb4j</groupId>
    <artifactId>kerb4j-server-tomcat</artifactId>
    <version>0.0.5-SNAPSHOT</version>
</dependency>
```