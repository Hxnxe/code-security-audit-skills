# Audit Dimensions (D1–D13)

| ID | Dimension | One-Line Definition |
|----|-----------|---------------------|
| D1 | Injection | User input reaches SQL/CMD/LDAP/SSTI execution points |
| D2 | Authentication | Token generation, validation, expiration completeness |
| D3 | Authorization | Sensitive operations verify ownership/permission |
| D4 | Deserialization | Untrusted data deserialized |
| D5 | File Operations | Upload/download paths user-controllable |
| D6 | SSRF | Server-side HTTP request URLs user-controllable |
| D7 | Cryptography | Hardcoded keys, weak algorithms, insecure random |
| D8 | Configuration | Debug endpoints, CORS, verbose errors, DoS/ReDoS |
| D9 | Business Logic | Race conditions, workflow bypass, price manipulation |
| D10 | Supply Chain | Dependencies with known CVEs |
| D11 | Info Disclosure | Public endpoints expose PII/configs/secrets/internal state |
| D12 | Data Exposure | Non-admin responses include unnecessary sensitive fields |
| D13 | Non-Runtime Assets | `.env`/`*.sql`/seeders/migrations contain exploitable credentials or bootstrap secrets |
