if Code.ensure_loaded?(Plug) do
  defmodule HTTPDigest.Plug do
    @moduledoc """
    Verifies `Content-Digest` on incoming Plug requests.

    Because `Plug.Parsers` consumes the raw body, digest computation must be
    hooked into body reading:

        plug Plug.Parsers,
          parsers: [:json],
          json_decoder: JSON,
          body_reader: {HTTPDigest.Plug, :read_body, []}

        plug HTTPDigest.Plug, required: true

    On failure, the default response is 403 with `Want-Content-Digest`.
    Override it with `:on_failure`.
    """

    @behaviour Plug

    import Plug.Conn

    alias HTTPDigest.{Algorithms, Error}

    @impl true
    def init(opts) do
      Keyword.validate!(opts,
        required: false,
        supported: [:sha256, :sha512],
        policy: :strongest,
        allow_insecure: false,
        on_failure: nil
      )
    end

    @doc """
    A `body_reader` for `Plug.Parsers` that folds raw request body chunks into
    a digest stream stored in `conn.private[:http_digest_stream]`.
    """
    @spec read_body(Plug.Conn.t(), keyword()) ::
            {:ok, binary(), Plug.Conn.t()}
            | {:more, binary(), Plug.Conn.t()}
            | {:error, term()}
    def read_body(conn, opts) do
      case Plug.Conn.read_body(conn, opts) do
        {:ok, chunk, conn} -> {:ok, chunk, fold(conn, chunk)}
        {:more, chunk, conn} -> {:more, chunk, fold(conn, chunk)}
        {:error, _} = err -> err
      end
    end

    defp fold(conn, chunk) do
      case conn.private[:http_digest_stream] || init_stream(conn) do
        nil -> conn
        stream -> put_private(conn, :http_digest_stream, HTTPDigest.Stream.update(stream, chunk))
      end
    end

    defp init_stream(conn) do
      with [header | _] <- get_req_header(conn, "content-digest"),
           {:ok, digests} <- HTTPDigest.parse_content_digest(header),
           algs = for({alg, _} <- digests, is_atom(alg), Algorithms.crypto_alg(alg), do: alg),
           [_ | _] <- algs do
        {:ok, stream} = HTTPDigest.Stream.init(algorithms: algs, allow_insecure: true)
        stream
      else
        _ -> nil
      end
    end

    @impl true
    def call(conn, opts) do
      case get_req_header(conn, "content-digest") do
        [] ->
          if opts[:required],
            do: fail(conn, opts, %Error{reason: :no_supported_algorithm}),
            else: conn

        [header | _] ->
          computed =
            case conn.private[:http_digest_stream] do
              nil -> empty_body_digests(conn)
              stream -> HTTPDigest.Stream.digests(stream)
            end

          verify_opts = Keyword.take(opts, [:supported, :policy, :allow_insecure])

          case HTTPDigest.verify_digests(computed, header, verify_opts) do
            {:ok, alg} -> put_private(conn, :http_digest_verified, alg)
            {:error, error} -> fail(conn, opts, error)
          end
      end
    end

    defp empty_body_digests(conn) do
      case init_stream(conn) do
        nil -> %{}
        stream -> HTTPDigest.Stream.digests(stream)
      end
    end

    defp fail(conn, opts, error) do
      case opts[:on_failure] do
        fun when is_function(fun, 2) ->
          fun.(conn, error)

        nil ->
          {:ok, want} = HTTPDigest.build_want_content_digest(want_prefs(opts[:supported]))

          conn
          |> put_resp_header("want-content-digest", want)
          |> send_resp(403, "Content-Digest verification failed")
          |> halt()
      end
    end

    defp want_prefs(supported) do
      supported
      |> Enum.sort_by(&Algorithms.strength/1, :desc)
      |> Enum.with_index()
      |> Enum.map(fn {alg, i} -> {alg, max(10 - i, 1)} end)
    end
  end
end
