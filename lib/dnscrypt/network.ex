defmodule Dnscrypt.Network do
  @moduledoc """
  A general purpose (supporting both TCP and UDP) networking api.
  """

  alias Dnscrypt.Types.{Certificate, Response}
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

  @spec send_tcp_request(
          resolver_ip :: String.t(),
          resolver_port :: number(),
          data :: binary()
        ) :: {:ok, Response.t()}
  def send_tcp_request(resolver_ip, resolver_port, data) when is_binary(data) do
    length = 1

    with {:ok, socket} <- :gen_tcp.connect(resolver_ip, resolver_port, [:binary, active: false]),
         :ok <- :gen_tcp.send(socket, data),
         {:ok, response} when is_binary(response) <- :gen_tcp.recv(socket, length),
         %Response{} = dns_response <- Response.from_binary(response) do
      {:ok, dns_response}
    end
  end
end
