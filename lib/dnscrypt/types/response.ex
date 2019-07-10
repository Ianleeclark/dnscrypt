defmodule Dnscrypt.Types.Response do
  @moduledoc false

  # TODO(ian): How long?
  @nonce_bit_len 96

  @required_keys [:client_nonce, :resolver_nonce, :response]
  @enforce_keys @required_keys
  defstruct @required_keys

  @type t :: %__MODULE__{
          client_nonce: binary(),
          resolver_nonce: binary(),
          # TODO(ian): Expand response to the true value
          response: binary()
        }

  @doc """
  Parses a dns response into this type.

  <<114, 54, 102, 110, 118, 87, 106, 56>> Represents the client magic, a static value defined in the 2.0 protocol

  """
  @spec from_binary(binary()) :: t() | {:error, :invalid_query_response}
  def from_binary(
        <<114, 54, 102, 110, 118, 87, 106, 56, client_nonce::size(@nonce_bit_len),
          resolver_nonce::size(@nonce_bit_len), response::binary()>>
      ) do
    %__MODULE__{
      client_nonce: client_nonce,
      resolver_nonce: resolver_nonce,
      response: response
    }
  end

  def from_binary(_), do: {:error, :invalid_query_response}
end
