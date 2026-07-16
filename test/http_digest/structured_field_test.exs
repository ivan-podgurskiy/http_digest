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

  describe "parse_dictionary/1" do
    test "parses byte sequence members" do
      digest = :crypto.hash(:sha256, ~s({"hello": "world"}))

      assert SF.parse_dictionary("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:") ==
               {:ok, [{"sha-256", {:binary, digest}}]}
    end

    test "parses multi-member dictionaries with flexible OWS" do
      assert {:ok, members} = SF.parse_dictionary("sha-512=10,sha-256=5")
      assert members == [{"sha-512", {:integer, 10}}, {"sha-256", {:integer, 5}}]

      assert {:ok, ^members} = SF.parse_dictionary("sha-512=10,   sha-256=5")
      assert {:ok, ^members} = SF.parse_dictionary("  sha-512=10, sha-256=5  ")
    end

    test "parses negative integers" do
      assert SF.parse_dictionary("a=-42") == {:ok, [{"a", {:integer, -42}}]}
    end

    test "empty input is an empty dictionary" do
      assert SF.parse_dictionary("") == {:ok, []}
      assert SF.parse_dictionary("   ") == {:ok, []}
    end

    test "duplicate keys: last wins" do
      assert SF.parse_dictionary("a=1, b=2, a=3") ==
               {:ok, [{"b", {:integer, 2}}, {"a", {:integer, 3}}]}
    end

    test "malformed inputs fail" do
      for bad <- [
            "a=",
            "a=1,",
            ",a=1",
            "a=1 b=2",
            "A=1",
            "a=:!!!:",
            "a=:aGk:extra",
            "a=:aGk",
            "a=1.5",
            ~s(a="str"),
            "a=?1",
            "a",
            "a=(1 2)",
            "a=1;p=1",
            "a=9999999999999999"
          ] do
        assert SF.parse_dictionary(bad) == {:error, :malformed}, "expected failure for: #{bad}"
      end
    end
  end
end
