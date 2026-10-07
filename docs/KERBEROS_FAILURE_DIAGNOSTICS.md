# Kerberos Failure Diagnostics

Kerberos errors are usually emitted by JAAS, JGSS, Apache Kerby, or the KDC. Their messages are useful for search engines and AI models, but they are not friendly API contracts. Kerb4J now keeps those original exceptions as causes and adds stable diagnostics in `com.kerb4j.common.exception`.

## New Exception Model

All diagnostic exceptions extend `Kerb4JKerberosException` and expose:

- `getFailureCode()` - stable enum value such as `CLOCK_SKEW_TOO_LARGE`.
- `getFailureCategory()` - broad bucket such as `CLOCK`, `CREDENTIALS`, `ENCRYPTION`, or `SPNEGO_TOKEN`.
- `getDiagnostic()` - summary, likely causes, suggested actions, operation, original exception type, and original message.
- `getCause()` - the original provider exception is preserved for stack traces and model-assisted troubleshooting.

Public checked-exception methods remain for compatibility. Prefer the new convenience methods when you want actionable runtime exceptions:

- `SpnegoClient.createContextOrThrow(URL)`
- `SpnegoClient.createContextForSPNOrThrow(String)`
- `SpnegoClient.createAuthorizationHeader(URL)`
- `SpnegoClient.createAuthorizationHeaderForSPN(String)`
- `SpnegoClient.createAcceptContextOrThrow()`
- `SpnegoContext.createTokenOrThrow()`
- `SpnegoContext.createTokenAsAuthorizationHeader()`
- `SpnegoContext.acceptTokenOrThrow(byte[])`

Spring server integrations still throw Spring `BadCredentialsException` / `AuthenticationServiceException`, but their message and cause now carry the Kerb4J diagnostic exception.

## Common Failures

| Common provider/KDC message | Typical cause | Old Kerb4J behavior | New diagnostic |
| --- | --- | --- | --- |
| `Clock skew too great` | Client, server, or KDC clocks differ too much | Raw `LoginException`/`GSSException`, often wrapped in `RuntimeException` or `BadCredentialsException` | `KerberosClockSkewException`, `CLOCK_SKEW_TOO_LARGE` |
| `Cannot locate default realm` | Missing `default_realm` or unqualified principal | Raw provider exception | `KerberosConfigurationException`, `REALM_NOT_CONFIGURED` |
| `Cannot find KDC for realm`, `Unable to locate KDC` | Missing realm KDC config or DNS discovery failure | Raw provider exception or provider-specific `IllegalStateException` | `KerberosCommunicationException`, `KDC_NOT_FOUND` |
| Connection refused, timeout, unknown host | KDC host exists but is unreachable | Raw nested network/provider exception | `KerberosCommunicationException`, `KDC_UNREACHABLE` |
| `Client not found in Kerberos database` | User/client principal is wrong or missing | Raw provider exception | `KerberosCredentialException`, `CLIENT_PRINCIPAL_NOT_FOUND` |
| `Server not found in Kerberos database` | Requested SPN is not registered | Raw `GSSException` or generic Spring bad credentials | `KerberosServicePrincipalException`, `SERVER_PRINCIPAL_NOT_FOUND` |
| Pre-authentication failed | Wrong password/keytab, disabled account, AD policy issue | Raw `LoginException`/Kerby exception | `KerberosCredentialException`, `PREAUTHENTICATION_FAILED` |
| Ticket or credentials expired | TGT/service ticket expired or renewal failed | Subject refresh often became generic runtime failure | `KerberosCredentialException`, `CREDENTIALS_EXPIRED` |
| Missing ticket cache / `KRB5CCNAME` | Cache login requested but no readable FILE ccache exists | Kerby-specific `IllegalStateException` or JAAS error | `KerberosCredentialException`, `TICKET_CACHE_NOT_FOUND` |
| No TGT / `failed to find any Kerberos tgt` | Accept-only subject used for outbound auth, or empty cache | Raw provider exception | `KerberosCredentialException`, `TGT_NOT_FOUND` |
| Keytab missing/unreadable | Wrong path or permissions; classpath keytab used where JAAS needs a file | Raw `LoginException` or config exception | `KerberosConfigurationException`, `KEYTAB_NOT_FOUND` |
| Keytab missing principal | `servicePrincipal` does not match keytab entries | Generic login/decryption failure | `KerberosCredentialException`, `KEYTAB_MISSING_PRINCIPAL` |
| KVNO/key version mismatch | Service account password changed after keytab generation | Checksum/decryption/GSS failure | `KerberosEncryptionException`, `KEY_VERSION_MISMATCH` |
| Unsupported enctype / cannot find key type | KDC issued an enctype not available in keytab/JVM policy | Raw provider/GSS failure | `KerberosEncryptionException`, `UNSUPPORTED_ENCRYPTION_TYPE` |
| Checksum failed / message stream modified | Wrong service key, wrong SPN, corrupted token, or ticket for another service | Generic Spring `BadCredentialsException` on accept | `KerberosEncryptionException`, `CANNOT_DECRYPT_TICKET` |
| Request is a replay | Same authenticator/token reused | Raw GSS/KDC error | `SpnegoTokenException`, `REPLAY_DETECTED` |
| Defective token / ASN.1 / malformed | Bad Base64 extraction, truncated header, or non-SPNEGO token | `Kerb4JException` in parser or generic Spring failure | `SpnegoTokenException`, `TOKEN_MALFORMED` |
| Unsupported mechanism / NTLM fallback | Client sent Negotiate but selected non-Kerberos mechanism | Raw token/GSS failure | `SpnegoTokenException`, `UNSUPPORTED_MECHANISM` |
| Enterprise principal unsupported by JDK provider | Provider capability mismatch | `UnsupportedOperationException` | `KerberosProviderException`, `UNSUPPORTED_OPERATION` |

## Troubleshooting Contract

Applications should catch the specific subclass when they need behavior, and log `getDiagnostic().toSupportString()` for support tickets. Do not parse provider messages for control flow.

Example:

```java
try {
    String header = spnegoClient.createAuthorizationHeaderForSPN("HTTP/app.example.com");
} catch (Kerb4JKerberosException e) {
    switch (e.getFailureCode()) {
        case CLOCK_SKEW_TOO_LARGE:
            // Tell the operator to check NTP.
            break;
        case SERVER_PRINCIPAL_NOT_FOUND:
            // Tell the operator to check SPN registration and URL hostname.
            break;
        default:
            // Include e.getDiagnostic().toSupportString() in logs.
    }
}
```
