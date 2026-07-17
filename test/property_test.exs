defmodule HTTPDigestPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise
  import StreamData

  alias HTTPDigest.StructuredField, as: SF

  property "verify(body, content_digest(body)) always succeeds" do
    check all(
            body <- binary(),
            algs <- member_of([[:sha256], [:sha512], [:sha256, :sha512]])
          ) do
      {:ok, header} = HTTPDigest.content_digest(body, algorithms: algs)
      assert {:ok, alg} = HTTPDigest.verify_content(body, header)
      assert alg in algs
    end
  end

  property "any single bit flip in the body is a digest_mismatch" do
    check all(
            body <- binary(min_length: 1),
            pos <- integer(0..(byte_size(body) * 8 - 1))
          ) do
      <<pre::size(pos), bit::1, post::bitstring>> = body
      tampered = <<pre::size(pos), bxor(bit, 1)::1, post::bitstring>>

      {:ok, header} = HTTPDigest.content_digest(body, algorithms: [:sha256, :sha512])

      assert {:error, %HTTPDigest.Error{reason: :digest_mismatch}} =
               HTTPDigest.verify_content(tampered, header)
    end
  end

  property "SF roundtrip: parse(serialize(members)) == members" do
    check all(
            members <-
              uniq_list_of(tuple({sf_key(), sf_value()}),
                uniq_fun: &elem(&1, 0),
                min_length: 1,
                max_length: 8
              )
          ) do
      {:ok, serialized} = SF.serialize_dictionary(members)
      assert SF.parse_dictionary(serialized) == {:ok, members}
    end
  end

  property "Want roundtrip through build and parse" do
    check all(
            prefs <-
              uniq_list_of(
                tuple({member_of([:sha256, :sha512, :md5, :sha]), integer(0..10)}),
                uniq_fun: &elem(&1, 0),
                min_length: 1,
                max_length: 3
              )
          ) do
      {:ok, header} = HTTPDigest.build_want_content_digest(prefs)
      assert HTTPDigest.parse_want_content_digest(header) == {:ok, Map.new(prefs)}
    end
  end

  property "parser never raises on arbitrary input" do
    check all(garbage <- binary(max_length: 128)) do
      case SF.parse_dictionary(garbage) do
        {:ok, _} -> :ok
        {:error, :malformed} -> :ok
      end
    end
  end

  defp sf_key do
    gen all(
          first <- member_of(Enum.map(?a..?z, &<<&1>>) ++ ["*"]),
          rest <-
            string(
              Enum.to_list(?a..?z) ++ Enum.to_list(?0..?9) ++ [?_, ?-, ?., ?*],
              max_length: 12
            )
        ) do
      first <> rest
    end
  end

  defp sf_value do
    one_of([
      map(binary(max_length: 64), &{:binary, &1}),
      map(integer(-999_999_999_999_999..999_999_999_999_999), &{:integer, &1})
    ])
  end
end
