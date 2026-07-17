defmodule HTTPDigest.Stream do
  @moduledoc """
  Incremental digest computation for large bodies.

  This wraps `:crypto.hash_init/1`, `:crypto.hash_update/2`, and
  `:crypto.hash_final/1` while preserving the same algorithm policy as the
  one-shot `HTTPDigest.content_digest/2` API.

      {:ok, stream} = HTTPDigest.Stream.init(algorithms: [:sha256])
      stream = HTTPDigest.Stream.update(stream, chunk1)
      stream = HTTPDigest.Stream.update(stream, chunk2)
      {:ok, header_value} = HTTPDigest.Stream.content_digest(stream)
  """

  alias HTTPDigest.{Algorithms, Error, StructuredField}

  defstruct algorithms: [], states: %{}

  @opaque t :: %__MODULE__{algorithms: [atom()], states: %{atom() => term()}}

  @spec init(keyword()) :: {:ok, t()} | {:error, Error.t()}
  def init(opts \\ []) do
    algorithms = Keyword.get(opts, :algorithms, [:sha256])
    allow_insecure = Keyword.get(opts, :allow_insecure, false)

    case Enum.find(algorithms, &(not Algorithms.verifiable?(&1, allow_insecure))) do
      nil ->
        states = Map.new(algorithms, &{&1, :crypto.hash_init(Algorithms.crypto_alg(&1))})
        {:ok, %__MODULE__{algorithms: algorithms, states: states}}

      bad ->
        {:error, %Error{reason: :insecure_algorithm_refused, algorithm: bad}}
    end
  end

  @spec update(t(), iodata()) :: t()
  def update(%__MODULE__{states: states} = stream, iodata) do
    %{
      stream
      | states: Map.new(states, fn {alg, st} -> {alg, :crypto.hash_update(st, iodata)} end)
    }
  end

  @spec digests(t()) :: %{atom() => binary()}
  def digests(%__MODULE__{states: states}) do
    Map.new(states, fn {alg, st} -> {alg, :crypto.hash_final(st)} end)
  end

  @spec content_digest(t()) :: {:ok, String.t()}
  def content_digest(%__MODULE__{} = stream), do: finalize(stream)

  @spec repr_digest(t()) :: {:ok, String.t()}
  def repr_digest(%__MODULE__{} = stream), do: finalize(stream)

  defp finalize(%__MODULE__{algorithms: algorithms} = stream) do
    digests = digests(stream)

    members =
      for alg <- algorithms, do: {Algorithms.to_iana(alg), {:binary, Map.fetch!(digests, alg)}}

    StructuredField.serialize_dictionary(members)
  end
end
