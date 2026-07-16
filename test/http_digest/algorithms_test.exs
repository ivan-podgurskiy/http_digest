defmodule HTTPDigest.AlgorithmsTest do
  use ExUnit.Case, async: true

  alias HTTPDigest.Algorithms

  test "maps IANA keys to atoms and back" do
    assert Algorithms.from_iana("sha-256") == {:ok, :sha256}
    assert Algorithms.from_iana("sha-512") == {:ok, :sha512}
    assert Algorithms.from_iana("md5") == {:ok, :md5}
    assert Algorithms.from_iana("sha") == {:ok, :sha}
    assert Algorithms.from_iana("unixsum") == {:ok, :unixsum}
    assert Algorithms.from_iana("unixcksum") == {:ok, :unixcksum}
    assert Algorithms.from_iana("blake2") == :error
    assert Algorithms.to_iana(:sha256) == "sha-256"
    assert Algorithms.to_iana(:sha512) == "sha-512"
  end

  test "statuses mirror the IANA registry" do
    assert Algorithms.status(:sha256) == :active
    assert Algorithms.status(:sha512) == :active

    for alg <- [:md5, :sha, :unixsum, :unixcksum] do
      assert Algorithms.status(alg) == :insecure
    end
  end

  test "strength gives a strict total order with sha-512 on top" do
    strengths =
      Enum.map([:sha512, :sha256, :sha, :md5, :unixcksum, :unixsum], &Algorithms.strength/1)

    assert strengths == Enum.sort(strengths, :desc)
    assert length(Enum.uniq(strengths)) == 6
  end

  test "verifiable? gates on status and crypto support" do
    assert Algorithms.verifiable?(:sha256, false)
    refute Algorithms.verifiable?(:md5, false)
    assert Algorithms.verifiable?(:md5, true)
    assert Algorithms.verifiable?(:sha, true)
    refute Algorithms.verifiable?(:unixsum, true)
    refute Algorithms.verifiable?(:unixcksum, true)
  end

  test "crypto_alg is nil only for the unix checksums" do
    assert Algorithms.crypto_alg(:sha256) == :sha256
    assert Algorithms.crypto_alg(:sha) == :sha
    assert Algorithms.crypto_alg(:unixsum) == nil
  end
end
