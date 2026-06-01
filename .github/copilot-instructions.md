# Copilot instructions for Kerb4J

- Keep changes focused and minimal; do not refactor unrelated code.
- This is a multi-module Maven project targeting Java 17.
- When changing Java code, run tests with:
  - `mvn -B clean test -U`
- Preserve existing module boundaries (`kerb4j-common`, `kerb4j-client`, `kerb4j-server`).
- Follow existing coding style and package structure.
- Never commit `krb5.conf` (must remain gitignored).
- Never add license information to Markdown files or to code comments.
- Never add yourself to `@author` Javadoc tags.
- Use JSpecify annotations such as `@NonNull` and `@Nullable` in new code you write.
- Where relevant, create integration tests using `com.kerb4j.KerberosSecurityTestcase` for setting up a mock Kerberos server. See `com.kerb4j.client.SpnegoHttpURLConnectionTests` as an example.