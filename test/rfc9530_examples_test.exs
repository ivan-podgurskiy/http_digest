defmodule RFC9530ExamplesTest do
  use ExUnit.Case, async: true

  @json_no_lf ~s({"hello": "world"})
  @json_with_lf @json_no_lf <> "\n"
  @range_content :binary.part(@json_with_lf, 10, 9)

  @sha256_no_lf "X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="
  @sha512_no_lf "WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew=="
  @md5_no_lf "Sd/dVLAcvNLSq16eXua5uQ=="
  @sha1_no_lf "07CavjDP4u3/TungoUHJO/Wzr4c="

  @sha256_with_lf "RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg="
  @sha512_with_lf "YMAam51Jz/jOATT6/zvHrLVgOYTGFy1d6GJiOHTohq4yP+pgk4vf2aCsyRZOtw8MjkM7iw7yZ/WkppmM44T3qg=="
  @sha256_empty "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
  @sha256_range "jjcgBDWNAtbYUXI37CVG3gRuGOAjaaDRGpIUFsdyepQ="

  test "Appendix D sample digest values match local crypto" do
    assert Base.encode64(:crypto.hash(:sha256, @json_no_lf)) == @sha256_no_lf
    assert Base.encode64(:crypto.hash(:sha512, @json_no_lf)) == @sha512_no_lf
    assert Base.encode64(:crypto.hash(:md5, @json_no_lf)) == @md5_no_lf
    assert Base.encode64(:crypto.hash(:sha, @json_no_lf)) == @sha1_no_lf
  end

  test "Appendix D values build and verify through digest fields" do
    assert HTTPDigest.content_digest(@json_no_lf, algorithms: [:sha256, :sha512]) ==
             {:ok, "sha-256=:#{@sha256_no_lf}:, sha-512=:#{@sha512_no_lf}:"}

    md5_header = "md5=:#{@md5_no_lf}:"

    assert {:error, %HTTPDigest.Error{reason: :insecure_algorithm_refused, algorithm: :md5}} =
             HTTPDigest.verify_content(@json_no_lf, md5_header, supported: [:md5])

    assert HTTPDigest.verify_content(@json_no_lf, md5_header,
             supported: [:md5],
             allow_insecure: true
           ) == {:ok, :md5}
  end

  test "Appendix B.1 full response has identical Content-Digest and Repr-Digest" do
    assert Base.encode64(:crypto.hash(:sha256, @json_with_lf)) == @sha256_with_lf
    header = "sha-256=:#{@sha256_with_lf}:"

    assert HTTPDigest.content_digest(@json_with_lf) == {:ok, header}
    assert HTTPDigest.repr_digest(@json_with_lf) == {:ok, header}
    assert HTTPDigest.verify_content(@json_with_lf, header) == {:ok, :sha256}
    assert HTTPDigest.verify_repr(@json_with_lf, header) == {:ok, :sha256}
  end

  test "Appendix B.2 HEAD response uses empty content but non-empty representation" do
    assert Base.encode64(:crypto.hash(:sha256, "")) == @sha256_empty
    content_header = "sha-256=:#{@sha256_empty}:"
    repr_header = "sha-256=:#{@sha256_with_lf}:"

    assert HTTPDigest.content_digest("") == {:ok, content_header}
    assert HTTPDigest.repr_digest(@json_with_lf) == {:ok, repr_header}
  end

  test "Appendix B.3 range response content differs from representation" do
    assert @range_content == "\"world\"}\n"
    assert Base.encode64(:crypto.hash(:sha256, @range_content)) == @sha256_range

    assert HTTPDigest.content_digest(@range_content) == {:ok, "sha-256=:#{@sha256_range}:"}
    assert HTTPDigest.repr_digest(@json_with_lf) == {:ok, "sha-256=:#{@sha256_with_lf}:"}
  end

  test "Section 4 and Appendix C Want-Repr-Digest examples parse and select predictably" do
    assert HTTPDigest.parse_want_repr_digest("sha-512=3, sha-256=10, unixsum=0") ==
             {:ok, %{sha512: 3, sha256: 10, unixsum: 0}}

    assert HTTPDigest.select_from_want("sha-256=3, sha=10", supported: [:sha256, :sha512]) ==
             {:ok, :sha256}

    assert HTTPDigest.select_from_want("sha=10", supported: [:sha256, :sha512]) ==
             {:error, %HTTPDigest.Error{reason: :no_supported_algorithm}}
  end

  test "Appendix C.2 server-selected sha-512 verifies even when the request wanted sha" do
    header = "sha-512=:#{@sha512_with_lf}:"
    assert HTTPDigest.verify_repr(@json_with_lf, header) == {:ok, :sha512}
  end
end
