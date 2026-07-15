defmodule HTTPDigest.ErrorTest do
  use ExUnit.Case, async: true

  test "carries reason and optional algorithm" do
    e = %HTTPDigest.Error{reason: :digest_mismatch, algorithm: :sha512}
    assert e.reason == :digest_mismatch
    assert e.algorithm == :sha512
  end

  test "is raisable with a readable message" do
    e = %HTTPDigest.Error{reason: :insecure_algorithm_refused, algorithm: :md5}
    assert Exception.message(e) =~ "insecure_algorithm_refused"
    assert Exception.message(e) =~ "md5"
    assert Exception.message(%HTTPDigest.Error{reason: :empty_header}) =~ "empty_header"
  end
end
