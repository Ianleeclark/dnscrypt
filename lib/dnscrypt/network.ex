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
          data :: binary(),
          opts :: Keyword.t()
        ) :: {:ok, Response.t()}
  def send_tcp_request(resolver_ip, resolver_port, data, opts \\ [timeout: 1_000])
      when is_binary(data) do
    timeout = Access.get(opts, :timeout, 2_000)
    length = 64
    ip_tuple = string_ip_to_tuple(resolver_ip)

    with {:ok, socket} <-
           :gen_tcp.connect(ip_tuple, resolver_port, [
             :binary,
             active: false
           ]),
         IO.inspect("Connected"),
         :ok <- :gen_tcp.send(socket, data),
         IO.inspect("Sent data"),
         {:ok, response} when is_binary(response) <- :gen_tcp.recv(socket, length, timeout),
         IO.inspect(response),
         %Response{} = dns_response <- Response.from_binary(response) do
      IO.inspect(dns_response)
      {:ok, dns_response}
    end
  end

  @spec string_ip_to_tuple(ip :: String.t()) :: {integer(), integer(), integer(), integer()}
  defp string_ip_to_tuple(ip) when is_bitstring(ip) do
    [oct1, oct2, oct3, oct4] = String.split(ip, ".")

    {String.to_integer(oct1), String.to_integer(oct2), String.to_integer(oct3),
     String.to_integer(oct4)}
  end
end
