defmodule Dnscrypt do
  @moduledoc """
  Documentation for Dnscrypt.
  """

  alias Dnscrypt.Network
  alias Dnscrypt.Utils.Crypto
  alias Dnscrypt.Types.{Certificate, Query}

  # TODO(ian): Determine how this info will be provided
  @client_sk :crypto.strong_rand_bytes(32)
  @client_pk :crypto.strong_rand_bytes(32)

  @spec query(
          hostname :: String.t(),
          resolver_host :: String.t(),
          resolver_ip :: String.t(),
          resolver_port :: non_neg_integer()
        ) :: any()
  # TODO(ian): Support opts like timeout
  def query(hostname, resolver_host, resolver_ip, resolver_port)
      when is_bitstring(hostname) and is_bitstring(resolver_ip) and is_bitstring(resolver_host) and
             is_number(resolver_port) do
    client_magic = :crypto.strong_rand_bytes(8)

    with {:ok, %Certificate{es_version: algorithm, public_key: resolver_public_key}} <-
           Network.fetch_dns_certificate(resolver_host, resolver_ip, resolver_port),
         {:ok, shared_key} <-
           Crypto.derive_shared_key(algorithm, @client_sk, resolver_public_key),
         {:ok, client_nonce} <- Crypto.nonce(algorithm),
         # TODO(ian): Remove the encrypted query from query.new
         %Query{} = query <- Query.new(client_magic, @client_pk, client_nonce, nil, algorithm),
         {:ok, encrypted_query} <-
           Crypto.encrypt_query(algorithm, shared_key, client_nonce, nil, query, nil),
         %Query{} = final_query <-
           Query.new(
             client_magic,
             @client_pk,
             client_nonce,
             encrypted_query,
             algorithm
           ),
         binary_query when is_binary(binary_query) <- Query.to_binary(final_query),
         {:ok, _x} <- Network.send_tcp_request(resolver_ip, resolver_port, binary_query) do
      {:ok, shared_key}
    end
  end
end
