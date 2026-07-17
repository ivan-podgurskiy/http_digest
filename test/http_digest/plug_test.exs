if Code.ensure_loaded?(Plug) and Code.ensure_loaded?(JSON) do
  defmodule HTTPDigest.PlugTest do
    use ExUnit.Case, async: true

    import Plug.Conn
    import Plug.Test

    @body ~s({"hello": "world"})

    defp pipeline(body, headers, plug_opts \\ []) do
      conn =
        Enum.reduce(headers, conn(:post, "/", body), fn {k, v}, c -> put_req_header(c, k, v) end)
        |> put_req_header("content-type", "application/json")

      parser_opts =
        Plug.Parsers.init(
          parsers: [:json],
          json_decoder: JSON,
          body_reader: {HTTPDigest.Plug, :read_body, []}
        )

      conn
      |> Plug.Parsers.call(parser_opts)
      |> HTTPDigest.Plug.call(HTTPDigest.Plug.init(plug_opts))
    end

    test "valid digest passes and records the verified algorithm" do
      {:ok, digest} = HTTPDigest.content_digest(@body)
      conn = pipeline(@body, [{"content-digest", digest}])

      refute conn.halted
      assert conn.private[:http_digest_verified] == :sha256
      assert conn.body_params == %{"hello" => "world"}
    end

    test "tampered digest gets 403 with Want-Content-Digest" do
      {:ok, digest} = HTTPDigest.content_digest("something else")
      conn = pipeline(@body, [{"content-digest", digest}])

      assert conn.halted
      assert conn.status == 403
      assert ["sha-512=10, sha-256=9"] = get_resp_header(conn, "want-content-digest")
    end

    test "missing header passes unless required" do
      conn = pipeline(@body, [])
      refute conn.halted

      conn = pipeline(@body, [], required: true)
      assert conn.halted
      assert conn.status == 403
    end

    test "malformed header is rejected" do
      conn = pipeline(@body, [{"content-digest", "garbage !!"}])
      assert conn.halted
      assert conn.status == 403
    end

    test "custom failure handler" do
      on_failure = fn conn, %HTTPDigest.Error{} = e ->
        conn |> send_resp(422, Exception.message(e)) |> halt()
      end

      {:ok, digest} = HTTPDigest.content_digest("other")
      conn = pipeline(@body, [{"content-digest", digest}], on_failure: on_failure)

      assert conn.status == 422
      assert conn.resp_body =~ "digest_mismatch"
    end

    test "digest over empty body verifies when parsers never read a body" do
      {:ok, digest} = HTTPDigest.content_digest("")

      conn =
        conn(:get, "/")
        |> put_req_header("content-digest", digest)
        |> HTTPDigest.Plug.call(HTTPDigest.Plug.init([]))

      refute conn.halted
      assert conn.private[:http_digest_verified] == :sha256
    end
  end
end
