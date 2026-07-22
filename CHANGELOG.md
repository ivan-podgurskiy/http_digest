# Changelog

## v0.1.0 (2026-07-22)

- Build and parse RFC 9530 `Content-Digest` and `Repr-Digest` field values.
- Verify digest fields with a downgrade-aware `:strongest` policy and optional
  `:any` compatibility policy.
- Build, parse, and select algorithms from `Want-Content-Digest` and
  `Want-Repr-Digest`.
- Compute digests incrementally with `HTTPDigest.Stream`.
- Optional `HTTPDigest.Plug` integration for incoming request verification.
- Optional `HTTPDigest.Req` integration for outgoing `Content-Digest` fields.
- Scoped RFC 8941 Structured Fields Dictionary parser/serializer for the value
  types used by RFC 9530.
