if Code.ensure_loaded?(JSON) do
  defmodule HTTPDigest.SFVectorsTest do
    use ExUnit.Case, async: true

    alias HTTPDigest.StructuredField, as: SF

    defp to_members(expected) do
      expected
      |> Enum.reduce_while({:ok, []}, fn
        [key, [value, []]], {:ok, acc} ->
          case to_value(value) do
            {:ok, v} -> {:cont, {:ok, [{key, v} | acc]}}
            :unsupported -> {:halt, :unsupported}
          end

        [_key, [_value, _params]], _acc ->
          {:halt, :unsupported}
      end)
      |> case do
        {:ok, acc} -> {:ok, Enum.reverse(acc)}
        :unsupported -> :unsupported
      end
    end

    defp to_value(i) when is_integer(i), do: {:ok, {:integer, i}}

    defp to_value(%{"__type" => "binary", "value" => b32}),
      do: {:ok, {:binary, Base.decode32!(b32)}}

    defp to_value(_), do: :unsupported

    vectors_dir = Path.expand("../vectors", __DIR__)

    all_cases =
      ["dictionary.json", "binary.json", "number.json"]
      |> Enum.flat_map(fn file ->
        vectors_dir |> Path.join(file) |> File.read!() |> JSON.decode!()
      end)
      |> Enum.filter(&(&1["header_type"] == "dictionary"))

    for {case_, idx} <- Enum.with_index(all_cases) do
      %{"name" => name} = case_
      @case case_
      name = "#{idx}: #{name}"

      if case_["must_fail"] do
        test "must_fail #{name}" do
          raw = Enum.join(@case["raw"], ", ")
          assert SF.parse_dictionary(raw) == {:error, :malformed}
        end
      else
        test "vector #{name}" do
          raw = Enum.join(@case["raw"], ", ")

          case to_members(@case["expected"]) do
            :unsupported ->
              assert SF.parse_dictionary(raw) == {:error, :malformed}

            {:ok, []} ->
              assert SF.parse_dictionary(raw) == {:ok, []}

            {:ok, members} ->
              assert SF.parse_dictionary(raw) == {:ok, members}

              if canonical = @case["canonical"] do
                assert {:ok, serialized} = SF.serialize_dictionary(members)
                assert [serialized] == canonical
              end
          end
        end
      end
    end
  end
end
