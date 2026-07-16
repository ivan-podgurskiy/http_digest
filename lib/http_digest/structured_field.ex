defmodule HTTPDigest.StructuredField do
  @moduledoc false
  # Strictly-scoped RFC 8941 subset: Dictionary whose member values are
  # Byte Sequences or Integers, no parameters. This is intentionally not a
  # general Structured Fields implementation because digest fields need only
  # this subset, and anything outside the subset should fail closed.

  @max_int 999_999_999_999_999
  @min_int -999_999_999_999_999

  @type member_value :: {:binary, binary()} | {:integer, integer()}
  @type members :: [{String.t(), member_value()}]

  @spec serialize_dictionary(members()) :: {:ok, String.t()} | {:error, atom()}
  def serialize_dictionary([]), do: {:error, :empty}

  def serialize_dictionary(members) when is_list(members) do
    with {:ok, parts} <- serialize_members(members, []) do
      {:ok, Enum.join(parts, ", ")}
    end
  end

  defp serialize_members([], acc), do: {:ok, Enum.reverse(acc)}

  defp serialize_members([{key, value} | rest], acc) do
    with :ok <- validate_key(key),
         {:ok, serialized} <- serialize_value(value) do
      serialize_members(rest, [key <> "=" <> serialized | acc])
    end
  end

  defp serialize_value({:binary, bytes}) when is_binary(bytes),
    do: {:ok, ":" <> Base.encode64(bytes) <> ":"}

  defp serialize_value({:integer, i}) when is_integer(i) and i >= @min_int and i <= @max_int,
    do: {:ok, Integer.to_string(i)}

  defp serialize_value({:integer, i}) when is_integer(i), do: {:error, :integer_out_of_range}
  defp serialize_value(_), do: {:error, :unsupported_value}

  defp validate_key(<<c, rest::binary>>) when c in ?a..?z or c == ?*, do: validate_key_rest(rest)
  defp validate_key(_), do: {:error, :invalid_key}

  defp validate_key_rest(<<>>), do: :ok

  defp validate_key_rest(<<c, rest::binary>>)
       when c in ?a..?z or c in ?0..?9 or c in [?_, ?-, ?., ?*],
       do: validate_key_rest(rest)

  defp validate_key_rest(_), do: {:error, :invalid_key}
end
