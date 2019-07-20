defmodule Dnscrypt.Utils.Crypto do
  @moduledoc false

  alias Salty.Box.{Curve25519xchacha20poly1305, Curve25519xsalsa20poly1305}
  alias Dnscrypt.Types.Query

  import Dnscrypt.Utils.Guards

  @spec encrypt_query(
          algorithm :: Query.algorithm(),
          shared_key :: binary(),
          client_nonce :: binary(),
          client_nonce_pad :: binary(),
          client_query :: binary(),
          client_query_pad :: binary()
        ) :: {:ok, binary()} | {:error, :failed_to_encrypt_query}
  def encrypt_query(
        algorithm,
        shared_key,
        client_nonce,
        # TODO(ian): Are these _pad necessary, or can I just use `create_padding`?
        _client_nonce_pad,
        client_query,
        _client_query_pad
      )
      when is_valid_encryption_algorithm(algorithm) do
    # NOTE: The client_nonce is only half the required length, the rest should be null-padded
    padded_nonce = client_nonce <> create_padding(byte_size(client_nonce))
    query = Query.to_binary(client_query)

    # TODO(ian): DOnt keep as a static len -- spec says random
    query_padding = <<80>> <> create_padding(173)

    client_nonce_padding = create_padding(12)

    query_to_encrypt = query <> query_padding

    finalized_key = shared_key <> client_nonce <> client_nonce_padding
    IO.inspect(shared_key)

    # TODO(ian): Do whatever is necessary after this case, not complete
    try do
      case algorithm do
        :xchacha20poly1305 ->
          Curve25519xchacha20poly1305.easy_afternm(query_to_encrypt, padded_nonce, finalized_key)

        :xsalsa20poly1305 ->
          Curve25519xsalsa20poly1305.easy_afternm(query_to_encrypt, padded_nonce, finalized_key)
      end
    rescue
      x ->
        IO.inspect(x)
        {:error, :failed_to_encrypt_query}
    end
  end

  @spec derive_shared_key(
          algorithm :: atom,
          client_sk :: binary(),
          resolver_pk :: binary()
        ) ::
          {:ok, binary()}
          | {:error, :failed_to_derive_shared_key}
          | {:error, :invalid_shared_key_derivation_data}
  def derive_shared_key(:xchacha20poly1305, client_sk, resolver_pk)
      when is_binary_of_octet_size(client_sk, 32) and is_binary_of_octet_size(resolver_pk, 32) do
    case Curve25519xchacha20poly1305.beforenm(client_sk, resolver_pk) do
      {:ok, _key} = response -> response
      _ -> {:error, :failed_to_derive_shared_key}
    end
  end

  def derive_shared_key(:xsalsa20poly1305, client_sk, resolver_pk)
      when is_binary_of_octet_size(client_sk, 32) and is_binary_of_octet_size(resolver_pk, 32) do
    case Curve25519xsalsa20poly1305.beforenm(client_sk, resolver_pk) do
      {:ok, _key} = response -> response
      _ -> {:error, :failed_to_derive_shared_key}
    end
  end

  @doc """
  Creates a variable-length group of null bytes

  ## Examples:

      iex> Dnscrypt.Utils.Crypto.create_padding(1)
      << 0 >>

      iex> Dnscrypt.Utils.Crypto.create_padding(5)
      << 0, 0, 0, 0, 0 >>

      iex> Dnscrypt.Utils.Crypto.create_padding(3)
      "\x00\x00\x00"
  """
  @spec create_padding(padding_len :: non_neg_integer()) :: binary()
  def create_padding(padding_len) when is_number(padding_len) do
    Enum.into(1..padding_len, <<>>, fn _ ->
      <<0>>
    end)
  end

  # TODO(ian): Move these magic numbers to constants
  def nonce(:xsalsa20poly1305), do: {:ok, :crypto.strong_rand_bytes(24)}

  def nonce(:xchacha20poly1305), do: {:ok, :crypto.strong_rand_bytes(24)}
end
