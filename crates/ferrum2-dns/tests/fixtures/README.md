# M12 encrypted-DNS test fixtures

These files are synthetic test-only artifacts generated locally with `OpenSSL 4.0.1 9 Jun 2026`.
They contain no production identity or secret. The CA private key and generation intermediates were
deleted after signing; only the leaf private key required by the local test server is retained.

| File | Purpose | Bytes | SHA-256 |
|---|---|---:|---|
| `m12-test-ca.der` | P-256 self-signed test CA certificate | 389 | `9d663938e7f28c1404bb7d8e27b0930c303a990bdaf9f3c16a0e5fddcefccd2c` |
| `m12-resolver-test.der` | P-256 leaf certificate, SAN `DNS:resolver.test` | 408 | `aca34e22c4ab2ba8f83d3670854192860e9bd379dec21e948efff05a7dc35796` |
| `m12-resolver-test.pk8` | Unencrypted PKCS#8 leaf key for the local server | 138 | `5309a360915ca5b912e9b4597b573bc4d01bdf67776cc150e16d250893610f6c` |

Both certificates are valid from `2026-08-05 07:35:12 UTC` through
`2036-08-02 07:35:12 UTC`. The CA has critical `CA:TRUE` and certificate-signing usage; the leaf is
issued by that CA and has only the `resolver.test` DNS identity.

Generation used ephemeral files under `.tmp-m12-cert` and these commands (line wrapping added):

```text
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 \
  -subj "/CN=ferrum2 M12 test CA" -days 3650 \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 \
  -subj "/CN=resolver.test" -addext "subjectAltName=DNS:resolver.test"
openssl x509 -req -CA ca.pem -CAkey ca.key -CAcreateserial -days 3650 -sha256 \
  -copy_extensions copy
openssl x509 -in ca.pem -outform der -out m12-test-ca.der
openssl x509 -in leaf.pem -outform der -out m12-resolver-test.der
openssl pkcs8 -topk8 -nocrypt -in leaf.key -outform der -out m12-resolver-test.pk8
```

The artifacts are repository-authored test data under the project's `GPL-3.0-only` license.
