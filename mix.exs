defmodule HTTPDigest.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/ivan-podgurskiy/http_digest"

  def project do
    [
      app: :http_digest,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "HTTPDigest",
      description:
        "RFC 9530 Digest Fields for Elixir: build, parse, and verify Content-Digest, " <>
          "Repr-Digest, and Want-* headers.",
      package: package(),
      source_url: @source_url,
      docs: docs()
    ]
  end

  def application do
    [extra_applications: [:crypto]]
  end

  defp deps do
    [
      {:plug, "~> 1.14", optional: true},
      {:req, "~> 0.5", optional: true},
      {:stream_data, "~> 1.1", only: [:dev, :test]},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE CHANGELOG.md),
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "RFC 9530" => "https://www.rfc-editor.org/rfc/rfc9530"
      },
      maintainers: ["Ivan Podgurskiy"]
    ]
  end

  defp docs do
    [
      main: "HTTPDigest",
      source_ref: "v#{@version}",
      source_url: @source_url,
      extras: ["README.md", "CHANGELOG.md", "LICENSE"]
    ]
  end
end
