defmodule HTTPDigestTest do
  use ExUnit.Case, async: true
  doctest HTTPDigest

  @body ~s({"hello": "world"})

  describe "content_digest/2" do
    test "builds a sha-256 header by default" do
      assert HTTPDigest.content_digest(@body) ==
               {:ok, "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"}
    end

    test "builds multi-algorithm headers in requested order" do
      assert {:ok, value} = HTTPDigest.content_digest(@body, algorithms: [:sha256, :sha512])
      assert value =~ "sha-256=:"
      assert value =~ ", sha-512=:"

      expected_512 = Base.encode64(:crypto.hash(:sha512, @body))
      assert value =~ "sha-512=:#{expected_512}:"
    end

    test "accepts iodata" do
      assert HTTPDigest.content_digest([~s({"hello": ), [~s("world"), ?}]]) ==
               HTTPDigest.content_digest(@body)
    end

    test "refuses insecure algorithms without opt-in" do
      assert {:error, %HTTPDigest.Error{reason: :insecure_algorithm_refused, algorithm: :md5}} =
               HTTPDigest.content_digest(@body, algorithms: [:md5])

      assert {:ok, "md5=:" <> _} =
               HTTPDigest.content_digest(@body, algorithms: [:md5], allow_insecure: true)
    end

    test "never builds unixsum/unixcksum even with opt-in" do
      assert {:error, %HTTPDigest.Error{reason: :insecure_algorithm_refused, algorithm: :unixsum}} =
               HTTPDigest.content_digest(@body, algorithms: [:unixsum], allow_insecure: true)
    end
  end

  describe "repr_digest/2" do
    test "is byte-identical in mechanics to content_digest/2" do
      assert HTTPDigest.repr_digest(@body) == HTTPDigest.content_digest(@body)
    end
  end
end
