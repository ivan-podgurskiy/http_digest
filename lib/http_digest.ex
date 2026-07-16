defmodule HTTPDigest do
  @moduledoc """
  RFC 9530 Digest Fields: build, parse, and verify `Content-Digest`,
  `Repr-Digest`, `Want-Content-Digest`, and `Want-Repr-Digest`.

  ## Content vs Representation

  `Content-Digest` covers the actual message content bytes, what is on the
  wire after any content coding. `Repr-Digest` covers the selected
  representation, which under `Content-Encoding: gzip` or a `Range` request
  is a different byte string. RFC 3230's single `Digest` field was obsoleted
  precisely because it never said which of the two it meant.

  This library never guesses: you pass the bytes, it hashes them. For
  `Repr-Digest` you must pass the representation bytes as you define them.
  """

  alias HTTPDigest.{Algorithms, Error, StructuredField}

  @default_algorithms [:sha256]

  @doc """
  Builds a `Content-Digest` header value over `body` (iodata).

      iex> HTTPDigest.content_digest(~s({"hello": "world"}))
      {:ok, "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"}

  Options:

    * `:algorithms` - list of `:sha256` / `:sha512` (default `[:sha256]`)
    * `:allow_insecure` - permit `:md5` / `:sha` (default `false`)
  """
  @spec content_digest(iodata(), keyword()) :: {:ok, String.t()} | {:error, Error.t()}
  def content_digest(body, opts \\ []), do: build_digest(body, opts)

  @doc """
  Builds a `Repr-Digest` header value over the representation bytes.

  Mechanically identical to `content_digest/2`; the caller is responsible for
  supplying the representation bytes, such as the uncompressed document when
  the message content is gzip-coded, or the full document on a range response.
  """
  @spec repr_digest(iodata(), keyword()) :: {:ok, String.t()} | {:error, Error.t()}
  def repr_digest(representation, opts \\ []), do: build_digest(representation, opts)

  defp build_digest(body, opts) do
    algorithms = Keyword.get(opts, :algorithms, @default_algorithms)
    allow_insecure = Keyword.get(opts, :allow_insecure, false)

    with :ok <- validate_buildable(algorithms, allow_insecure) do
      members =
        for alg <- algorithms do
          {Algorithms.to_iana(alg), {:binary, :crypto.hash(Algorithms.crypto_alg(alg), body)}}
        end

      {:ok, value} = StructuredField.serialize_dictionary(members)
      {:ok, value}
    end
  end

  defp validate_buildable(algorithms, allow_insecure) do
    Enum.find_value(algorithms, :ok, fn alg ->
      if Algorithms.known?(alg) and Algorithms.verifiable?(alg, allow_insecure) do
        nil
      else
        {:error, %Error{reason: :insecure_algorithm_refused, algorithm: alg}}
      end
    end)
  end
end
