# HTTPDigest

[![CI](https://github.com/ivan-podgurskiy/http_digest/actions/workflows/ci.yml/badge.svg)](https://github.com/ivan-podgurskiy/http_digest/actions/workflows/ci.yml)
[![Hex pm](https://img.shields.io/hexpm/v/http_digest.svg)](https://hex.pm/packages/http_digest)
[![HexDocs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/http_digest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

RFC 9530 Digest Fields for Elixir: build, parse, and verify `Content-Digest`,
`Repr-Digest`, and `Want-*` headers.

## Installation

Add `http_digest` to the dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:http_digest, "~> 0.1"}
  ]
end
```

Requires OTP 25 or later.

## License

MIT © Ivan Podgurskiy. See [LICENSE](LICENSE).
