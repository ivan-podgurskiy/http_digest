# HTTPDigest

[![CI](https://github.com/ivan-podgurskiy/http_digest/actions/workflows/ci.yml/badge.svg)](https://github.com/ivan-podgurskiy/http_digest/actions/workflows/ci.yml)
[![Hex pm](https://img.shields.io/hexpm/v/http_digest.svg)](https://hex.pm/packages/http_digest)
[![HexDocs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/http_digest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

RFC 9530 Digest Fields for Elixir: build, parse, and verify `Content-Digest`,
`Repr-Digest`, and `Want-*` headers.

## Why RFC 9530, not RFC 3230

RFC 3230 defined a single `Digest` field, but did not clearly separate the
bytes on the wire from the selected representation. That distinction matters:
under content codings such as gzip or br, and under range responses, the HTTP
message content and the representation are different byte strings.

RFC 9530 obsoletes that ambiguity by splitting the field into
`Content-Digest` and `Repr-Digest`. `Content-Digest` covers message content
bytes. `Repr-Digest` covers selected representation bytes.

`HTTPDigest` implements the RFC 9530 fields and Structured Fields syntax. It
does not implement RFC 3230 compatibility mode. If you are migrating from a
package that emits the old `Digest` header, treat this as the newer layer.

## Installation

Add `http_digest` to the dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:http_digest, "~> 0.1"}
  ]
end
```

Requires OTP 25 or later because verification uses `:crypto.hash_equals/2` for
constant-time comparison.

## Quick Start

Build and verify a `Content-Digest` field:

```elixir
body = ~s({"hello": "world"})

{:ok, header} = HTTPDigest.content_digest(body)
#=> {:ok, "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"}

HTTPDigest.verify_content(body, header)
#=> {:ok, :sha256}
```

Build and parse a `Repr-Digest` field:

```elixir
representation = ~s({"hello": "world"}) <> "\n"

{:ok, header} = HTTPDigest.repr_digest(representation, algorithms: [:sha256])
{:ok, %{sha256: digest_bytes}} = HTTPDigest.parse_repr_digest(header)
```

Negotiate a response digest from `Want-*` fields:

```elixir
{:ok, want} = HTTPDigest.build_want_content_digest(sha512: 10, sha256: 5)
#=> {:ok, "sha-512=10, sha-256=5"}

HTTPDigest.select_from_want(want, supported: [:sha256, :sha512])
#=> {:ok, :sha512}
```

Hash a large body incrementally:

```elixir
{:ok, stream} = HTTPDigest.Stream.init(algorithms: [:sha256, :sha512])

stream =
  chunks
  |> Enum.reduce(stream, &HTTPDigest.Stream.update(&2, &1))

HTTPDigest.Stream.content_digest(stream)
```

Verify incoming Plug requests by hashing bytes as `Plug.Parsers` reads them:

```elixir
plug Plug.Parsers,
  parsers: [:json],
  json_decoder: JSON,
  body_reader: {HTTPDigest.Plug, :read_body, []}

plug HTTPDigest.Plug, required: true
```

Attach outgoing `Content-Digest` fields in Req:

```elixir
Req.new(base_url: "https://api.example.com")
|> HTTPDigest.Req.attach(digest_algorithms: [:sha256])
|> Req.post!(url: "/payments", body: encoded_body)
```

## Content vs Representation

This library never guesses what the representation is. Callers supply bytes.

For `Content-Digest`, pass the exact message content bytes. For
`Repr-Digest`, pass the selected representation bytes as your application
defines them. With `Content-Encoding: br`, for example, the content digest is
computed over the encoded bytes, while the representation digest is computed
over the selected representation associated with the response metadata.

The RFC 9530 examples make this visible: the JSON representation
`{"hello": "world"}\n` has a different digest than the byte range
`"world"}\n`, and an empty HEAD response can still carry a `Repr-Digest` for
the selected representation.

## Verification Policy

`HTTPDigest.verify_content/3`, `verify_repr/3`, and `verify_digests/3` default
to `policy: :strongest`. Among supported algorithms present in the field, the
strongest one is checked. A mismatch there fails verification even if a weaker
digest still matches.

| Header contains | `supported` | `policy` | `allow_insecure` | Outcome |
| --- | --- | --- | --- | --- |
| valid sha-512 + valid sha-256 | `[:sha256, :sha512]` | `:strongest` | `false` | `{:ok, :sha512}` |
| tampered sha-512 + valid sha-256 | `[:sha256, :sha512]` | `:strongest` | `false` | `{:error, :digest_mismatch}` |
| tampered sha-512 + valid sha-256 | `[:sha256, :sha512]` | `:any` | `false` | `{:ok, :sha256}` (downgrade-vulnerable) |
| valid sha-256 only | `[:sha256, :sha512]` | `:strongest` | `false` | `{:ok, :sha256}` |
| valid md5 only | `[:md5, :sha256]` | any | `false` | `{:error, :insecure_algorithm_refused}` |
| valid md5 only | `[:md5, :sha256]` | any | `true` | `{:ok, :md5}` |
| unknown algorithm only, such as blake2 | default | any | any | `{:error, :no_supported_algorithm}` |
| sha-512 only | `[:sha256]` | any | any | `{:error, :no_supported_algorithm}` |
| empty dictionary | any | any | any | `{:error, :empty_header}` |
| invalid Structured Fields syntax | any | any | any | `{:error, :malformed_header}` |

## Downgrade Defense

RFC 9530 Section 6.6 describes a downgrade shape where an attacker tampers
with a stronger digest but leaves a weaker digest valid. A verifier that
accepts "any matching digest" can be tricked into accepting the message through
the weaker digest.

The default `:strongest` policy prevents that: once `sha-512` and `sha-256`
are both present and supported, `sha-512` decides the result. Use
`policy: :any` only when interoperability requires it and the downgrade risk is
acceptable for the application.

## API

- `HTTPDigest.content_digest/2` and `HTTPDigest.repr_digest/2` build digest
  field values from iodata.
- `HTTPDigest.parse_content_digest/2` and `HTTPDigest.parse_repr_digest/2`
  parse digest fields into raw digest bytes.
- `HTTPDigest.verify_content/3`, `HTTPDigest.verify_repr/3`, and
  `HTTPDigest.verify_digests/3` verify fields with downgrade-aware policy.
- `HTTPDigest.build_want_content_digest/1`, `build_want_repr_digest/1`,
  `parse_want_content_digest/1`, `parse_want_repr_digest/1`, and
  `select_from_want/2` handle integrity preference fields.
- `HTTPDigest.Stream` computes digests incrementally.
- `HTTPDigest.Plug` and `HTTPDigest.Req` are optional integrations, available
  when those packages are loaded.

## Relationship to HTTP Message Signatures

RFC 9421 HTTP Message Signatures can sign `content-digest` and `repr-digest`
fields. `HTTPDigest` provides that digest layer: build, parse, and verify the
field values first, then sign or verify them with a message-signatures
implementation.

## Development

```bash
mix deps.get
mix format --check-formatted
mix compile --warnings-as-errors
mix test
mix docs
mix hex.build
```

`scripts/differential_check.exs` is a dev-only cross-check against Python
hashlib and a Structured Fields parser when one is installed. It is not part
of the Hex package.

## License

MIT © Ivan Podgurskiy. See [LICENSE](LICENSE).
