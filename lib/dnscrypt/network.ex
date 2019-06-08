defmodule Dnscrypt.Network do
  @moduledoc """
  A general purpose (supporting both TCP and UDP) networking api.
  """

  alias Dnscrypt.Types.Certificate
  alias DNS

  @spec fetch_dns_certificate(
          hostname :: String.t(),
          resolver_ip :: String.t(),
          resolver_port :: number()
        ) :: {:ok, Certificate.t()} | {:error, :failed_to_fetch_resolver_certificate}
  def fetch_dns_certificate(hostname, resolver_ip, resolver_port) do
    case DNS.query(hostname, :txt, {resolver_ip, resolver_port}) do
      %DNS.Record{anlist: [%DNS.Resource{data: [data]} | _rest]} ->
        cert =
          data
          |> Enum.into(<<>>, fn x -> <<x>> end)
          |> Certificate.from_binary()

        {:ok, cert}

      _ ->
        {:error, :failed_to_fetch_resolver_certificate}
    end
  end
end
