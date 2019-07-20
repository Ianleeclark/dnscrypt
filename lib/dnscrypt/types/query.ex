defmodule Dnscrypt.Types.Query do
  @moduledoc """
  Defines what a DNS query is to our system.
  """

  import Dnscrypt.Utils.Guards

  #############
  # Constants #
  #############

  # Defined as `Salty.Secretbox.Xchacha20poly1305.{key,nonce}bytes`
  # Can't call, though due to nif loading post-compilation
  @xchacha_key_len 32
  # TODO(ian): nonce lens are used in several places, move to constants
  @xchacha_nonce_len 24

  # Defined as `Salty.Secretbox.Xsalsa20poly1305.{key,nonce}bytes`
  @xsalsa_key_len 32
  @xsalsa_nonce_len 24

  @client_magic_octet_len 8

  ####################
  # Type Definitions #
  ####################

  @type algorithm :: :xsalsa20poly1305 | :xchacha20poly1305
  @type t :: %__MODULE__{
          client_magic: binary(),
          client_pk: binary(),
          client_nonce: binary(),
          encrypted_query: binary() | nil,
          algorithm: algorithm()
        }

  #####################
  # Struct Definition #
  #####################

  @required_keys [:client_magic, :client_pk, :client_nonce, :encrypted_query, :algorithm]
  @enforce_keys @required_keys
  defstruct @required_keys

  ##############
  # Public API #
  ##############

  @doc """
  Creates a new Query
  """
  @spec new(
          client_magic :: binary(),
          client_pk :: binary(),
          client_nonce :: binary(),
          encrypted_query :: binary(),
          algorithm :: algorithm()
        ) :: __MODULE__.t() | {:error, :invalid_algorithm} | {:error, :invalid_query_data}
  def new(client_magic, client_pk, client_nonce, encrypted_query, algorithm)
      when is_valid_encryption_algorithm(algorithm) and
             is_binary_of_octet_size(client_magic, @client_magic_octet_len) and
             is_binary(client_pk) and is_binary(client_nonce) do
    %__MODULE__{
      client_magic: client_magic,
      client_pk: client_pk,
      client_nonce: client_nonce,
      encrypted_query: encrypted_query,
      algorithm: algorithm
    }
  end

  def new(_client_magic, _client_pk, _client_nonce, algorithm)
      when not is_valid_encryption_algorithm(algorithm) do
    {:error, :invalid_algorithm}
  end

  def new(_, _, _, _) do
    {:error, :invalid_query_data}
  end

  @doc """
  Converts query struct to binary.
  """
  @spec to_binary(t()) :: binary() | {:error, :invalid_query}
  def to_binary(
        %__MODULE__{
          algorithm: :xsalsa20poly1305
        } = query
      ) do
    do_to_binary(query, @xsalsa_key_len, @xsalsa_nonce_len)
  end

  def to_binary(
        %__MODULE__{
          algorithm: :xchacha20poly1305
        } = query
      ) do
    do_to_binary(query, @xchacha_key_len, @xchacha_nonce_len)
  end

  def to_binary(_), do: {:error, :invalid_query}

  ##############################
  # Internal Private Functions #
  ##############################

  @spec do_to_binary(t(), key_len :: non_neg_integer(), nonce_len :: non_neg_integer()) :: any()
  def do_to_binary(
        %__MODULE__{
          client_magic: magic,
          client_pk: pk,
          client_nonce: nonce,
          encrypted_query: encrypted_query
        },
        _key_len,
        _nonce_len
      )
      when is_nil(encrypted_query) do
    magic <> pk <> nonce
  end

  def do_to_binary(
        %__MODULE__{
          client_magic: magic,
          client_pk: pk,
          client_nonce: nonce,
          encrypted_query: encrypted_query
        },
        _key_len,
        _nonce_len
      )
      when not is_nil(encrypted_query) do
    magic <> pk <> nonce <> encrypted_query
  end
end
