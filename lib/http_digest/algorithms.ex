defmodule HTTPDigest.Algorithms do
  @moduledoc false
  # Mirrors the IANA "Hash Algorithms for HTTP Digest Fields" registry
  # (RFC 9530 Section 7.2). New Active registrations are additive minor releases.

  @registry %{
    sha512: %{iana: "sha-512", crypto: :sha512, status: :active, strength: 6},
    sha256: %{iana: "sha-256", crypto: :sha256, status: :active, strength: 5},
    sha: %{iana: "sha", crypto: :sha, status: :insecure, strength: 4},
    md5: %{iana: "md5", crypto: :md5, status: :insecure, strength: 3},
    unixcksum: %{iana: "unixcksum", crypto: nil, status: :insecure, strength: 2},
    unixsum: %{iana: "unixsum", crypto: nil, status: :insecure, strength: 1}
  }

  @from_iana Map.new(@registry, fn {atom, %{iana: iana}} -> {iana, atom} end)

  @spec from_iana(String.t()) :: {:ok, atom()} | :error
  def from_iana(key) when is_binary(key), do: Map.fetch(@from_iana, key)

  @spec to_iana(atom()) :: String.t()
  def to_iana(alg), do: Map.fetch!(@registry, alg).iana

  @spec crypto_alg(atom()) :: :crypto.hash_algorithm() | nil
  def crypto_alg(alg), do: Map.fetch!(@registry, alg).crypto

  @spec status(atom()) :: :active | :insecure
  def status(alg), do: Map.fetch!(@registry, alg).status

  @spec strength(atom()) :: non_neg_integer()
  def strength(alg), do: Map.fetch!(@registry, alg).strength

  @spec known?(atom()) :: boolean()
  def known?(alg), do: is_map_key(@registry, alg)

  @spec verifiable?(atom(), boolean()) :: boolean()
  def verifiable?(alg, allow_insecure) do
    case Map.fetch(@registry, alg) do
      {:ok, %{crypto: nil}} -> false
      {:ok, %{status: :active}} -> true
      {:ok, %{status: :insecure}} -> allow_insecure
      :error -> false
    end
  end
end
