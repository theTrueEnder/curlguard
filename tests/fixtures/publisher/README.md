# Inert offline publisher-verification fixtures

`artifact.txt` and `bundle.json` are copied from Sigstore's conformance corpus at
commit `e241c4ea6c83b4d8f03461e825f056b2c5eba3ed`; the trusted root is from Cosign
v3.1.3's public-good-instance test material. `provenance.json` records source URLs
and exact hashes. Read and verify these files as data only.

The signing identity belongs to Sigstore's deliberately public test OIDC beacon.
It is suitable only for these conformance tests and must not become an accepted
production publisher identity. Tests mutate copies to exercise wrong identities,
invalid signatures, changed payloads and incomplete inclusion proofs. No test
signs with or executes an artifact.
