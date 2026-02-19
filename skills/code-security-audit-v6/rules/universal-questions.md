# 8 Universal Security Questions

Q1. Trust boundary: Who can call this? (unauth / auth / admin)
Q2. Data entry: Where does user input come from? (params / query / body / headers / URL)
Q3. Data exit: What does the response contain? PII / secrets / internal state?
Q4. DB interaction: Does input reach a query? Is it parameterized?
Q5. Side effects: Does it mutate state? Is authorization verified?
Q6. External calls: Does it call other services? Is URL user-controlled?
Q7. Intent coherence: Does the code behavior match the endpoint name/docs?
Q8. Credential lifecycle: Are credentials/tokens created, rotated, revoked, and verified consistently?
