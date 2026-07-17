if Code.ensure_loaded?(Req) do
  defmodule HTTPDigest.Req do
    @moduledoc """
    A `Req` request step that computes and attaches `Content-Digest` on
    outgoing requests.

        Req.new(base_url: "https://api.example.com")
        |> HTTPDigest.Req.attach(digest_algorithms: [:sha256])
        |> Req.post!(url: "/payments", body: payload)

    Bodies that are not iodata, such as request streams or nil bodies, are
    passed through untouched.
    """

    @spec attach(Req.Request.t(), keyword()) :: Req.Request.t()
    def attach(%Req.Request{} = request, opts \\ []) do
      request
      |> Req.Request.register_options([:digest_algorithms])
      |> Req.Request.merge_options(opts)
      |> Req.Request.append_request_steps(http_digest: &put_content_digest/1)
    end

    defp put_content_digest(%Req.Request{body: body} = request)
         when is_binary(body) or is_list(body) do
      algorithms = Req.Request.get_option(request, :digest_algorithms, [:sha256])

      case HTTPDigest.content_digest(body, algorithms: algorithms) do
        {:ok, value} -> Req.Request.put_header(request, "content-digest", value)
        {:error, _} -> request
      end
    end

    defp put_content_digest(request), do: request
  end
end
