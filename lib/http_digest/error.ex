defmodule HTTPDigest.Error do
  @moduledoc """
  Error struct returned by all `HTTPDigest` functions.

  The `reason` atoms are a stable, SemVer-guarded contract:

    * `:malformed_header` - Structured Fields parse failure, or a dictionary
      value of the wrong type for the field
    * `:digest_mismatch` - computed digest differs (carries `algorithm`)
    * `:no_supported_algorithm` - header parsed, but no member intersects the
      `:supported` list
    * `:insecure_algorithm_refused` - only deprecated algorithms matched and
      `allow_insecure: true` was not set (carries `algorithm`)
    * `:empty_header` - header present but the dictionary is empty
    * `:unknown_algorithm` - `on_unknown: :error` and an unregistered key was
      present (carries `algorithm` as a string)
    * `:invalid_preference` - Want-* preference outside 0..10
  """

  defexception [:reason, :algorithm]

  @type reason ::
          :malformed_header
          | :digest_mismatch
          | :no_supported_algorithm
          | :insecure_algorithm_refused
          | :empty_header
          | :unknown_algorithm
          | :invalid_preference

  @type t :: %__MODULE__{reason: reason(), algorithm: atom() | String.t() | nil}

  @impl true
  def message(%__MODULE__{reason: reason, algorithm: nil}), do: "http_digest: #{reason}"

  def message(%__MODULE__{reason: reason, algorithm: algorithm}),
    do: "http_digest: #{reason} (algorithm: #{algorithm})"
end
