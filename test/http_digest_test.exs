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

  describe "parse_content_digest/2" do
    test "parses known algorithms to atom keys with raw digest bytes" do
      digest = :crypto.hash(:sha256, @body)

      assert HTTPDigest.parse_content_digest(
               "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
             ) == {:ok, %{sha256: digest}}
    end

    test "preserves unknown algorithms under string keys" do
      assert {:ok, map} = HTTPDigest.parse_content_digest("blake2=:aGVsbG8=:, sha-256=:aGk=:")
      assert map["blake2"] == "hello"
      assert map.sha256 == "hi"
    end

    test "on_unknown: :error rejects unknown algorithms" do
      assert {:error, %HTTPDigest.Error{reason: :unknown_algorithm, algorithm: "blake2"}} =
               HTTPDigest.parse_content_digest("blake2=:aGk=:", on_unknown: :error)
    end

    test "error taxonomy" do
      assert {:error, %HTTPDigest.Error{reason: :empty_header}} =
               HTTPDigest.parse_content_digest("")

      assert {:error, %HTTPDigest.Error{reason: :malformed_header}} =
               HTTPDigest.parse_content_digest("sha-256=oops")

      assert {:error, %HTTPDigest.Error{reason: :malformed_header}} =
               HTTPDigest.parse_content_digest("sha-256=5")
    end

    test "parse_repr_digest/2 is identical in mechanics" do
      header = "sha-256=:aGk=:"
      assert HTTPDigest.parse_repr_digest(header) == HTTPDigest.parse_content_digest(header)
    end
  end

  describe "verify_content/3" do
    test "verifies and reports which algorithm was checked" do
      {:ok, header} = HTTPDigest.content_digest(@body, algorithms: [:sha256, :sha512])
      assert HTTPDigest.verify_content(@body, header) == {:ok, :sha512}

      {:ok, header256} = HTTPDigest.content_digest(@body)
      assert HTTPDigest.verify_content(@body, header256) == {:ok, :sha256}
    end

    test "mismatch carries the algorithm" do
      {:ok, header} = HTTPDigest.content_digest(@body)

      assert {:error, %HTTPDigest.Error{reason: :digest_mismatch, algorithm: :sha256}} =
               HTTPDigest.verify_content("tampered", header)
    end

    test "downgrade defense: strongest policy fails on tampered strong digest" do
      {:ok, good256} = HTTPDigest.content_digest(@body, algorithms: [:sha256])
      bad512 = "sha-512=:" <> Base.encode64(:crypto.hash(:sha512, "attacker")) <> ":"
      header = good256 <> ", " <> bad512

      assert {:error, %HTTPDigest.Error{reason: :digest_mismatch, algorithm: :sha512}} =
               HTTPDigest.verify_content(@body, header)

      assert {:ok, :sha256} = HTTPDigest.verify_content(@body, header, policy: :any)
    end

    test "no intersection with supported" do
      assert {:error, %HTTPDigest.Error{reason: :no_supported_algorithm}} =
               HTTPDigest.verify_content(@body, "blake2=:aGk=:")

      {:ok, header} = HTTPDigest.content_digest(@body, algorithms: [:sha512])

      assert {:error, %HTTPDigest.Error{reason: :no_supported_algorithm}} =
               HTTPDigest.verify_content(@body, header, supported: [:sha256])
    end

    test "insecure algorithms refuse by default, verify with opt-in" do
      md5 = Base.encode64(:crypto.hash(:md5, @body))
      header = "md5=:#{md5}:"

      assert {:error, %HTTPDigest.Error{reason: :insecure_algorithm_refused, algorithm: :md5}} =
               HTTPDigest.verify_content(@body, header, supported: [:md5, :sha256])

      assert {:ok, :md5} =
               HTTPDigest.verify_content(@body, header,
                 supported: [:md5, :sha256],
                 allow_insecure: true
               )
    end

    test "malformed and empty headers propagate parse errors" do
      assert {:error, %HTTPDigest.Error{reason: :malformed_header}} =
               HTTPDigest.verify_content(@body, "not a header !!")

      assert {:error, %HTTPDigest.Error{reason: :empty_header}} =
               HTTPDigest.verify_content(@body, "")
    end
  end

  describe "verify_digests/3" do
    test "verifies against precomputed digests" do
      digests = %{sha256: :crypto.hash(:sha256, @body)}
      {:ok, header} = HTTPDigest.content_digest(@body)

      assert HTTPDigest.verify_digests(digests, header) == {:ok, :sha256}

      assert {:error, %HTTPDigest.Error{reason: :digest_mismatch}} =
               HTTPDigest.verify_digests(%{sha256: :crypto.hash(:sha256, "other")}, header)
    end

    test "selected algorithm missing from the computed map is a mismatch" do
      {:ok, header} = HTTPDigest.content_digest(@body, algorithms: [:sha512])

      assert {:error, %HTTPDigest.Error{reason: :digest_mismatch, algorithm: :sha512}} =
               HTTPDigest.verify_digests(%{sha256: :crypto.hash(:sha256, @body)}, header)
    end
  end

  describe "Want-* fields" do
    test "build_want_content_digest/1" do
      assert HTTPDigest.build_want_content_digest(sha512: 10, sha256: 5) ==
               {:ok, "sha-512=10, sha-256=5"}
    end

    test "preferences outside 0..10 are rejected" do
      assert {:error, %HTTPDigest.Error{reason: :invalid_preference}} =
               HTTPDigest.build_want_content_digest(sha256: 11)

      assert {:error, %HTTPDigest.Error{reason: :invalid_preference}} =
               HTTPDigest.build_want_content_digest(sha256: -1)
    end

    test "parse_want_content_digest/1" do
      assert HTTPDigest.parse_want_content_digest("sha-512=10, sha-256=5, blake2=3") ==
               {:ok, %{:sha512 => 10, :sha256 => 5, "blake2" => 3}}

      assert {:error, %HTTPDigest.Error{reason: :malformed_header}} =
               HTTPDigest.parse_want_content_digest("sha-256=:aGk=:")

      assert {:error, %HTTPDigest.Error{reason: :invalid_preference}} =
               HTTPDigest.parse_want_content_digest("sha-256=12")
    end

    test "select_from_want/2 picks highest preference, strength breaks ties" do
      assert HTTPDigest.select_from_want("sha-512=10, sha-256=5", supported: [:sha256, :sha512]) ==
               {:ok, :sha512}

      assert HTTPDigest.select_from_want("sha-512=3, sha-256=3", supported: [:sha256, :sha512]) ==
               {:ok, :sha512}

      assert HTTPDigest.select_from_want("sha-512=10, sha-256=5", supported: [:sha256]) ==
               {:ok, :sha256}
    end

    test "select_from_want/2: zero preference means not acceptable" do
      assert {:error, %HTTPDigest.Error{reason: :no_supported_algorithm}} =
               HTTPDigest.select_from_want("sha-256=0", supported: [:sha256])

      assert {:error, %HTTPDigest.Error{reason: :no_supported_algorithm}} =
               HTTPDigest.select_from_want("blake2=10", supported: [:sha256])
    end

    test "want repr variants share mechanics" do
      assert HTTPDigest.build_want_repr_digest(sha256: 3) == {:ok, "sha-256=3"}
      assert HTTPDigest.parse_want_repr_digest("sha-256=3") == {:ok, %{sha256: 3}}
    end
  end
end
