defmodule DnsCrypt.MixProject do
  use Mix.Project

  def project do
    [
      app: :dnscrypt,
      version: "0.1.0",
      elixir: "~> 1.8",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      elixirc_options: [warnings_as_errors: true]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:salty, "~> 0.1.3", hex: :libsalty},
      {:dns, "~> 2.1.2"},
      # Deployment, testing, &c.
      {:credo, "~> 1.0", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:stream_data, "~> 0.1", only: :test},
      {:dialyxir, "~> 1.0.0-rc.6", only: [:dev, :test], runtime: false}
    ]
  end

  defp aliases do
    [
      testall: ["credo", "test", "dialyzer"]
    ]
  end
end
