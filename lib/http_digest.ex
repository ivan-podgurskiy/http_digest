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
  @default_supported [:sha256, :sha512]

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

  @doc """
  Parses a `Content-Digest` header value into a map of algorithm to raw digest
  bytes.

  Known algorithms get atom keys such as `:sha256`. Unknown dictionary keys are
  preserved under string keys because RFC 9530 receivers must ignore unknown
  algorithms unless the caller opts into `on_unknown: :error`.
  """
  @spec parse_content_digest(binary(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def parse_content_digest(header, opts \\ []), do: parse_digest_header(header, opts)

  @doc "Parses a `Repr-Digest` header value. See `parse_content_digest/2`."
  @spec parse_repr_digest(binary(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def parse_repr_digest(header, opts \\ []), do: parse_digest_header(header, opts)

  @doc """
  Verifies a `Content-Digest` header against `body`.

  The default `:strongest` policy checks only the strongest digest present
  whose algorithm is supported, so a tampered strong digest fails even when a
  weaker digest still matches. `policy: :any` accepts the strongest matching
  digest and should only be used when compatibility requires it.
  """
  @spec verify_content(iodata(), binary(), keyword()) :: {:ok, atom()} | {:error, Error.t()}
  def verify_content(body, header, opts \\ []),
    do: verify(header, opts, fn alg -> :crypto.hash(Algorithms.crypto_alg(alg), body) end)

  @doc "Verifies a `Repr-Digest` header against representation bytes. See `verify_content/3`."
  @spec verify_repr(iodata(), binary(), keyword()) :: {:ok, atom()} | {:error, Error.t()}
  def verify_repr(representation, header, opts \\ []),
    do: verify_content(representation, header, opts)

  @doc """
  Verifies a digest header against precomputed digests, such as
  `%{sha256: <<...>>}` from a streaming body reader.
  """
  @spec verify_digests(%{optional(atom()) => binary()}, binary(), keyword()) ::
          {:ok, atom()} | {:error, Error.t()}
  def verify_digests(computed, header, opts \\ []) when is_map(computed),
    do: verify(header, opts, fn alg -> Map.get(computed, alg, :missing) end)

  @doc """
  Builds a `Want-Content-Digest` header value from `{algorithm, preference}`
  pairs.

  Preferences are integers from 0 to 10. A preference of 0 means not
  acceptable.

      iex> HTTPDigest.build_want_content_digest(sha512: 10, sha256: 5)
      {:ok, "sha-512=10, sha-256=5"}
  """
  @spec build_want_content_digest(keyword(integer())) :: {:ok, String.t()} | {:error, Error.t()}
  def build_want_content_digest(prefs), do: build_want(prefs)

  @doc "Builds a `Want-Repr-Digest` header value. See `build_want_content_digest/1`."
  @spec build_want_repr_digest(keyword(integer())) :: {:ok, String.t()} | {:error, Error.t()}
  def build_want_repr_digest(prefs), do: build_want(prefs)

  @doc """
  Parses a `Want-Content-Digest` header into a map of algorithm to preference.

  Known algorithms get atom keys. Unknown algorithms are preserved under string
  keys.
  """
  @spec parse_want_content_digest(binary()) :: {:ok, map()} | {:error, Error.t()}
  def parse_want_content_digest(header), do: parse_want(header)

  @doc "Parses a `Want-Repr-Digest` header. See `parse_want_content_digest/1`."
  @spec parse_want_repr_digest(binary()) :: {:ok, map()} | {:error, Error.t()}
  def parse_want_repr_digest(header), do: parse_want(header)

  @doc """
  Selects the response digest algorithm requested by a `Want-*` header.

  Among supported algorithms with preference greater than 0, the highest
  preference wins. Ties go to the stronger algorithm.
  """
  @spec select_from_want(binary(), keyword()) :: {:ok, atom()} | {:error, Error.t()}
  def select_from_want(header, opts) do
    supported = Keyword.fetch!(opts, :supported)

    with {:ok, prefs} <- parse_want(header) do
      candidates =
        for {alg, pref} <- prefs, is_atom(alg), alg in supported, pref > 0, do: {alg, pref}

      case candidates do
        [] ->
          {:error, %Error{reason: :no_supported_algorithm}}

        _ ->
          {alg, _} =
            Enum.max_by(candidates, fn {alg, pref} -> {pref, Algorithms.strength(alg)} end)

          {:ok, alg}
      end
    end
  end

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

  defp parse_digest_header(header, opts) do
    on_unknown = Keyword.get(opts, :on_unknown, :ignore)

    case StructuredField.parse_dictionary(header) do
      {:ok, []} ->
        {:error, %Error{reason: :empty_header}}

      {:ok, members} ->
        digest_map(members, on_unknown)

      {:error, :malformed} ->
        {:error, %Error{reason: :malformed_header}}
    end
  end

  defp digest_map(members, on_unknown) do
    Enum.reduce_while(members, {:ok, %{}}, fn
      {key, {:binary, bytes}}, {:ok, acc} ->
        case Algorithms.from_iana(key) do
          {:ok, alg} ->
            {:cont, {:ok, Map.put(acc, alg, bytes)}}

          :error when on_unknown == :ignore ->
            {:cont, {:ok, Map.put(acc, key, bytes)}}

          :error ->
            {:halt, {:error, %Error{reason: :unknown_algorithm, algorithm: key}}}
        end

      {_key, {:integer, _}}, _acc ->
        {:halt, {:error, %Error{reason: :malformed_header}}}
    end)
  end

  defp verify(header, opts, compute_fun) do
    supported = Keyword.get(opts, :supported, @default_supported)
    policy = Keyword.get(opts, :policy, :strongest)
    allow_insecure = Keyword.get(opts, :allow_insecure, false)

    with {:ok, digests} <- parse_digest_header(header, []) do
      present = for {alg, bytes} <- digests, is_atom(alg), alg in supported, do: {alg, bytes}

      verifiable =
        Enum.filter(present, fn {alg, _} -> Algorithms.verifiable?(alg, allow_insecure) end)

      cond do
        present == [] ->
          {:error, %Error{reason: :no_supported_algorithm}}

        verifiable == [] ->
          {alg, _} = Enum.max_by(present, fn {alg, _} -> Algorithms.strength(alg) end)
          {:error, %Error{reason: :insecure_algorithm_refused, algorithm: alg}}

        true ->
          verifiable
          |> Enum.sort_by(fn {alg, _} -> Algorithms.strength(alg) end, :desc)
          |> apply_policy(policy, compute_fun)
      end
    end
  end

  defp apply_policy([{alg, expected} | _], :strongest, compute_fun),
    do: check_digest(alg, expected, compute_fun)

  defp apply_policy([{strongest, _} | _] = ordered, :any, compute_fun) do
    Enum.find_value(ordered, fn {alg, expected} ->
      case check_digest(alg, expected, compute_fun) do
        {:ok, _} = ok -> ok
        {:error, _} -> nil
      end
    end) || {:error, %Error{reason: :digest_mismatch, algorithm: strongest}}
  end

  defp check_digest(alg, expected, compute_fun) do
    case compute_fun.(alg) do
      computed when is_binary(computed) and byte_size(computed) == byte_size(expected) ->
        if :crypto.hash_equals(computed, expected),
          do: {:ok, alg},
          else: {:error, %Error{reason: :digest_mismatch, algorithm: alg}}

      _missing_or_wrong_size ->
        {:error, %Error{reason: :digest_mismatch, algorithm: alg}}
    end
  end

  defp build_want(prefs) do
    if Enum.all?(prefs, fn {_alg, pref} -> is_integer(pref) and pref in 0..10 end) do
      members = for {alg, pref} <- prefs, do: {Algorithms.to_iana(alg), {:integer, pref}}
      {:ok, value} = StructuredField.serialize_dictionary(members)
      {:ok, value}
    else
      {:error, %Error{reason: :invalid_preference}}
    end
  end

  defp parse_want(header) do
    case StructuredField.parse_dictionary(header) do
      {:ok, []} ->
        {:error, %Error{reason: :empty_header}}

      {:ok, members} ->
        want_map(members)

      {:error, :malformed} ->
        {:error, %Error{reason: :malformed_header}}
    end
  end

  defp want_map(members) do
    Enum.reduce_while(members, {:ok, %{}}, fn
      {key, {:integer, pref}}, {:ok, acc} when pref in 0..10 ->
        case Algorithms.from_iana(key) do
          {:ok, alg} -> {:cont, {:ok, Map.put(acc, alg, pref)}}
          :error -> {:cont, {:ok, Map.put(acc, key, pref)}}
        end

      {_key, {:integer, _out_of_range}}, _acc ->
        {:halt, {:error, %Error{reason: :invalid_preference}}}

      {_key, {:binary, _}}, _acc ->
        {:halt, {:error, %Error{reason: :malformed_header}}}
    end)
  end
end
