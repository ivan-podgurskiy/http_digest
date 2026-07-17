defmodule HTTPDigest.StreamTest do
  use ExUnit.Case, async: true

  alias HTTPDigest.Stream

  @body ~s({"hello": "world"})

  test "chunked hashing equals one-shot hashing" do
    {:ok, stream} = Stream.init(algorithms: [:sha256, :sha512])

    stream =
      @body
      |> String.graphemes()
      |> Enum.chunk_every(4)
      |> Enum.reduce(stream, fn chunk, s -> Stream.update(s, Enum.join(chunk)) end)

    assert Stream.content_digest(stream) ==
             HTTPDigest.content_digest(@body, algorithms: [:sha256, :sha512])

    assert Stream.repr_digest(stream) == Stream.content_digest(stream)
  end

  test "digests/1 returns raw digest bytes and does not consume the stream" do
    {:ok, stream} = Stream.init()
    stream = Stream.update(stream, @body)

    assert Stream.digests(stream) == %{sha256: :crypto.hash(:sha256, @body)}
    assert Stream.digests(stream) == %{sha256: :crypto.hash(:sha256, @body)}
  end

  test "init respects the insecure gate" do
    assert {:error, %HTTPDigest.Error{reason: :insecure_algorithm_refused}} =
             Stream.init(algorithms: [:md5])

    assert {:ok, _} = Stream.init(algorithms: [:md5], allow_insecure: true)
  end

  test "empty stream digests the empty string" do
    {:ok, stream} = Stream.init()
    assert Stream.digests(stream) == %{sha256: :crypto.hash(:sha256, "")}
  end
end
