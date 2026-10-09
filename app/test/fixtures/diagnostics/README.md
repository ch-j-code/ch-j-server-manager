These certificates and the unencrypted server private key are PUBLIC, LOCAL TEST FIXTURES ONLY.
Never deploy them. The CA private key was discarded. No external service uses this key.
`server.pem` covers localhost, 127.0.0.1 and ::1 until 2045. `expired.pem` expired in 2021.
The tests inject `ca.pem` only into their local clients; application trust is never changed.
