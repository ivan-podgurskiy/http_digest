defmodule HTTPDigest.StructuredFieldTest do
  use ExUnit.Case, async: true

  alias HTTPDigest.StructuredField, as: SF

  describe "serialize_dictionary/1" do
    test "byte sequence members use colon-wrapped standard base64" do
      digest = :crypto.hash(:sha256, ~s({"hello": "world"}))

      assert SF.serialize_dictionary([{"sha-256", {:binary, digest}}]) ==
               {:ok, "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"}
    end

    test "multiple members join with comma-space, order preserved" do
      assert {:ok, out} =
               SF.serialize_dictionary([
                 {"sha-512", {:integer, 10}},
                 {"sha-256", {:integer, 5}}
               ])

      assert out == "sha-512=10, sha-256=5"
    end

    test "negative and boundary integers serialize" do
      assert SF.serialize_dictionary([{"a", {:integer, -999_999_999_999_999}}]) ==
               {:ok, "a=-999999999999999"}

      assert SF.serialize_dictionary([{"a", {:integer, 1_000_000_000_000_000}}]) ==
               {:error, :integer_out_of_range}
    end

    test "rejects invalid keys" do
      assert SF.serialize_dictionary([{"SHA-256", {:integer, 1}}]) == {:error, :invalid_key}
      assert SF.serialize_dictionary([{"1abc", {:integer, 1}}]) == {:error, :invalid_key}
      assert SF.serialize_dictionary([{"", {:integer, 1}}]) == {:error, :invalid_key}
      assert {:ok, _} = SF.serialize_dictionary([{"*ok-key.1_x*", {:integer, 1}}])
    end

    test "rejects empty member list and unsupported values" do
      assert SF.serialize_dictionary([]) == {:error, :empty}
      assert SF.serialize_dictionary([{"a", {:string, "x"}}]) == {:error, :unsupported_value}
    end
  end
end
