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

  @spec parse_dictionary(binary()) :: {:ok, members()} | {:error, :malformed}
  def parse_dictionary(input) when is_binary(input) do
    case input |> trim_sp() |> parse_members([]) do
      {:ok, members} -> {:ok, last_wins(members)}
      :error -> {:error, :malformed}
    end
  end

  defp parse_members("", acc), do: {:ok, Enum.reverse(acc)}

  defp parse_members(input, acc) do
    with {:ok, key, rest} <- parse_key(input),
         {:ok, value, rest} <- parse_eq_value(rest) do
      case skip_ows(rest) do
        "" ->
          {:ok, Enum.reverse([{key, value} | acc])}

        <<?,, rest::binary>> ->
          case skip_ows(rest) do
            "" -> :error
            next -> parse_members(next, [{key, value} | acc])
          end

        _other ->
          :error
      end
    end
  end

  defp parse_key(<<c, _::binary>> = input) when c in ?a..?z or c == ?*,
    do: take_key(input, <<>>)

  defp parse_key(_), do: :error

  defp take_key(<<c, rest::binary>>, acc)
       when c in ?a..?z or c in ?0..?9 or c in [?_, ?-, ?., ?*],
       do: take_key(rest, <<acc::binary, c>>)

  defp take_key(rest, acc), do: {:ok, acc, rest}

  defp parse_eq_value(<<?=, rest::binary>>), do: parse_value(rest)
  defp parse_eq_value(_), do: :error

  defp parse_value(<<?:, rest::binary>>) do
    with {:ok, b64, rest} <- take_until_colon(rest, <<>>),
         {:ok, bytes} <- decode_base64(b64) do
      {:ok, {:binary, bytes}, rest}
    else
      _ -> :error
    end
  end

  defp parse_value(<<?-, c, _::binary>> = input) when c in ?0..?9 do
    <<?-, rest::binary>> = input

    with {:ok, {:integer, i}, rest} <- take_digits(rest, <<>>) do
      {:ok, {:integer, -i}, rest}
    end
  end

  defp parse_value(<<c, _::binary>> = input) when c in ?0..?9, do: take_digits(input, <<>>)
  defp parse_value(_), do: :error

  defp take_digits(<<c, rest::binary>>, acc) when c in ?0..?9,
    do: take_digits(rest, <<acc::binary, c>>)

  defp take_digits(rest, acc) when byte_size(acc) in 1..15,
    do: {:ok, {:integer, String.to_integer(acc)}, rest}

  defp take_digits(_rest, _acc), do: :error

  defp take_until_colon(<<?:, rest::binary>>, acc), do: {:ok, acc, rest}

  defp take_until_colon(<<c, rest::binary>>, acc)
       when c in ?A..?Z or c in ?a..?z or c in ?0..?9 or c in [?+, ?/, ?=],
       do: take_until_colon(rest, <<acc::binary, c>>)

  defp take_until_colon(_, _), do: :error

  defp decode_base64(b64) do
    case Base.decode64(b64) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> Base.decode64(b64, padding: false)
    end
  end

  defp skip_ows(<<c, rest::binary>>) when c in [?\s, ?\t], do: skip_ows(rest)
  defp skip_ows(input), do: input

  defp trim_sp(input), do: String.trim(input, " ")

  defp last_wins(members) do
    {keys, values} =
      Enum.reduce(members, {[], %{}}, fn {key, value}, {keys, values} ->
        keys = if Map.has_key?(values, key), do: keys, else: [key | keys]
        {keys, Map.put(values, key, value)}
      end)

    keys
    |> Enum.reverse()
    |> Enum.map(&{&1, Map.fetch!(values, &1)})
  end
end
