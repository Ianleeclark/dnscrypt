defmodule Dnscrypt.Utils.Crypto do
  @moduledoc false

  alias Salty.Box.{Curve25519xchacha20poly1305, Curve25519xsalsa20poly1305}
  alias Dnscrypt.Types.Query

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
      ) do
    padded_nonce = client_nonce <> create_padding(12)

    # TODO(ian): Do whatever is necessary after this case, not complete
    try do
      case algorithm do
        :xchacha20poly1305 ->
          Curve25519xchacha20poly1305.easy_afternm(client_query, padded_nonce, shared_key)

        :xsalsa20poly1305 ->
          Curve25519xsalsa20poly1305.easy_afternm(client_query, padded_nonce, shared_key)
      end
    rescue
      _ -> {:error, :failed_to_encrypt_query}
    end
  end

  @spec derive_shared_key(
          algorithm :: Query.algorithm(),
          client_sk :: binary(),
          resolver_pk :: binary()
        ) ::
          {:ok, binary()}
          | {:error, :failed_to_derive_shared_key}
          | {:error, :invalid_shared_key_derivation_data}
  def derive_shared_key(:xchacha20poly1305, client_sk, resolver_pk)
      when is_binary(client_sk) and is_binary(resolver_pk) do
    case Curve25519xchacha20poly1305.beforenm(client_sk, resolver_pk) do
      {:ok, _derived_key} = response -> response
      _ -> {:error, :failed_to_derive_shared_key}
    end
  end

  def derive_shared_key(:xsalsa20poly1305, client_sk, resolver_pk)
      when is_binary(client_sk) and is_binary(resolver_pk) do
    case Curve25519xsalsa20poly1305.beforenm(client_sk, resolver_pk) do
      {:ok, _derived_key} = response -> response
      _ -> {:error, :failed_to_derive_shared_key}
    end
  end

  def derive_shared_key(_, _, _) do
    {:error, :invalid_shared_key_derivation_data}
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
end
