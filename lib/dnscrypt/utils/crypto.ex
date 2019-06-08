defmodule Dnscrypt.Utils.Crypto do
  @moduledoc false

  alias Dnscrypt.Types.Query

  @spec encrypt_query(
          algorithm :: Query.algorithm(),
          shared_key :: binary(),
          client_nonce :: binary(),
          client_nonce_pad :: binary(),
          client_query :: binary(),
          client_query_pad :: binary()
        ) :: {:ok, binary()}
  def encrypt_query(
        :xchacha20poly1305,
        shared_key,
        client_nonce,
        client_nonce_pad,
        client_query,
        client_query_pad
      ) do
    {:ok, <<0>>}
  end

  @spec derive_shared_key(client_sk :: binary(), resolver_pk :: binary()) ::
          {:ok, binary()} | {:error, :failed_to_derive_shared_key}
  def derive_shared_key(client_sk, resolver_pk)
      when is_binary(client_sk) and is_binary(resolver_pk) do
    {:ok, <<0>>}
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
