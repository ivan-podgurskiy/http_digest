if Code.ensure_loaded?(Req) do
  defmodule HTTPDigest.ReqTest do
    use ExUnit.Case, async: true

    @body ~s({"hello": "world"})

    defp echo_digest_plug(conn) do
      digest = conn |> Plug.Conn.get_req_header("content-digest") |> List.first("MISSING")
      Plug.Conn.send_resp(conn, 200, digest)
    end

    test "attaches Content-Digest to outgoing requests with a body" do
      resp =
        Req.new(plug: &echo_digest_plug/1)
        |> HTTPDigest.Req.attach()
        |> Req.post!(url: "/", body: @body)

      assert {:ok, resp.body} == HTTPDigest.content_digest(@body)
    end

    test "respects digest_algorithms option" do
      resp =
        Req.new(plug: &echo_digest_plug/1)
        |> HTTPDigest.Req.attach(digest_algorithms: [:sha512])
        |> Req.post!(url: "/", body: @body)

      assert {:ok, resp.body} == HTTPDigest.content_digest(@body, algorithms: [:sha512])
    end

    test "skips requests without a body" do
      resp =
        Req.new(plug: &echo_digest_plug/1)
        |> HTTPDigest.Req.attach()
        |> Req.get!(url: "/")

      assert resp.body == "MISSING"
    end
  end
end
