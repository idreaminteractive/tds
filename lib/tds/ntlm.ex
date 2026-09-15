defmodule Tds.NTLM do
  @moduledoc false

  # Port of microsoft/go-mssqldb integratedauth/ntlm (v1.8.0).
  # Type1 OEM domain/workstation, Type3 UTF-16. NTLMv2 when Type2 has target info.

  import Bitwise

  @signature "NTLMSSP\0"
  @negotiate 1
  @challenge 2
  @authenticate 3

  @negotiate_unicode 0x00000001
  @negotiate_ntlm 0x00000200
  @negotiate_oem_domain 0x00001000
  @negotiate_oem_workstation 0x00002000
  @negotiate_always_sign 0x00008000
  @negotiate_extended_session 0x00080000
  @negotiate_target_info 0x00800000

  @negotiate_flags @negotiate_unicode ||| @negotiate_ntlm ||| @negotiate_oem_domain |||
                     @negotiate_oem_workstation ||| @negotiate_always_sign |||
                     @negotiate_extended_session

  defstruct [:domain, :username, :password, :workstation]

  def from_opts(opts) when is_list(opts) do
    {domain, username} = split_user(opts[:domain], opts[:username])

    %__MODULE__{
      domain: domain,
      username: username,
      password: opts[:password] || "",
      workstation: opts[:workstation] || "HAYTERS"
    }
  end

  def type1(%__MODULE__{} = auth) do
    domain = auth.domain
    workstation = auth.workstation
    domain_len = byte_size(domain)
    workstation_len = byte_size(workstation)

    header = <<
      @signature::binary,
      @negotiate::little-32,
      @negotiate_flags::little-32,
      domain_len::little-16,
      domain_len::little-16,
      40::little-32,
      workstation_len::little-16,
      workstation_len::little-16,
      40 + domain_len::little-32,
      0::little-32,
      0::little-32
    >>

    header <> domain <> workstation
  end

  def type3(%__MODULE__{} = auth, type2, opts \\ []) when is_binary(type2) do
    if binary_part(type2, 0, 8) != @signature do
      raise ArgumentError, "invalid NTLM Type2 signature"
    end

    <<_::binary-size(8), type::little-32, _::binary>> = type2

    if type != @challenge do
      raise ArgumentError, "expected NTLM Type2, got #{type}"
    end

    <<_::binary-size(20), flags::little-32, challenge::binary-size(8), _::binary>> = type2

    {lm, nt} =
      if band(flags, @negotiate_extended_session) != 0 do
        extended_session(auth, type2, challenge, flags, opts)
      else
        {lm_response(challenge, auth.password), nt_response(challenge, auth.password)}
      end

    build_authenticate(lm, nt, flags, auth)
  end

  defp extended_session(auth, type2, challenge, flags, opts) do
    nonce = Keyword.get_lazy(opts, :nonce, &client_nonce/0)

    if band(flags, @negotiate_target_info) != 0 do
      target_info = target_info_fields!(type2)
      timestamp = Keyword.get_lazy(opts, :timestamp, &ntlm_timestamp/0)
      ntlmv2_payloads(auth, challenge, nonce, target_info, timestamp)
    else
      lm = nonce <> <<0::size(16)-unit(8)>>
      nt = ntlm_session_response(nonce, challenge, auth.password)
      {lm, nt}
    end
  end

  defp ntlmv2_payloads(auth, challenge, nonce, target_info, timestamp) do
    ntlm_hash = ntlm_hash16(auth.password)
    user_target = utf16le(String.upcase(auth.username) <> auth.domain)
    ntlm_v2_hash = hmac_md5(ntlm_hash, user_target)

    blob =
      <<0x01, 0x01, 0x00, 0x00, 0::32>> <>
        <<timestamp::big-64>> <>
        nonce <>
        <<0::32>> <>
        target_info <>
        <<0::32>>

    nt = hmac_md5(ntlm_v2_hash, challenge <> blob) <> blob
    lm = hmac_md5(ntlm_v2_hash, challenge <> nonce) <> nonce
    {lm, nt}
  end

  defp target_info_fields!(type2) when byte_size(type2) < 20 do
    raise ArgumentError, "NTLMv2 Type2 too short"
  end

  defp target_info_fields!(type2) do
    <<_::binary-size(42), info_max::little-16, info_offset::little-32, _::binary>> = type2
    finish = info_offset + info_max

    if byte_size(type2) < finish do
      raise ArgumentError, "NTLMv2 Type2 target info truncated"
    end

    binary_part(type2, info_offset, info_max)
  end

  defp build_authenticate(lm, nt, flags, auth) do
    domain16 = utf16le(auth.domain)
    user16 = utf16le(auth.username)
    workstation16 = utf16le(auth.workstation)
    lm_len = byte_size(lm)
    nt_len = byte_size(nt)
    domain_len = byte_size(domain16)
    user_len = byte_size(user16)
    workstation_len = byte_size(workstation16)

    header = <<
      @signature::binary,
      @authenticate::little-32,
      lm_len::little-16,
      lm_len::little-16,
      88::little-32,
      nt_len::little-16,
      nt_len::little-16,
      88 + lm_len::little-32,
      domain_len::little-16,
      domain_len::little-16,
      88 + lm_len + nt_len::little-32,
      user_len::little-16,
      user_len::little-16,
      88 + lm_len + nt_len + domain_len::little-32,
      workstation_len::little-16,
      workstation_len::little-16,
      88 + lm_len + nt_len + domain_len + user_len::little-32,
      0::little-16,
      0::little-16,
      88 + lm_len + nt_len + domain_len + user_len + workstation_len::little-32,
      flags::little-32,
      0::little-64,
      0::little-128
    >>

    header <> lm <> nt <> domain16 <> user16 <> workstation16
  end

  defp ntlm_hash16(password) do
    :crypto.hash(:md4, utf16le(password))
  end

  defp ntlm_hash21(password) do
    ntlm_hash16(password) <> <<0, 0, 0, 0, 0>>
  end

  defp nt_response(challenge, password) do
    des_response(challenge, ntlm_hash21(password))
  end

  defp lm_hash21(password) do
    lmpass = password |> String.upcase() |> binary_part_pad(14)
    magic = "KGS!@#$%"
    encrypt_des(binary_part(lmpass, 0, 7), magic) <> encrypt_des(binary_part(lmpass, 7, 7), magic) <> <<0, 0, 0, 0, 0>>
  end

  defp lm_response(challenge, password) do
    des_response(challenge, lm_hash21(password))
  end

  defp ntlm_session_response(client_nonce, server_challenge, password) do
    session = :crypto.hash(:md5, server_challenge <> client_nonce)
    hash8 = binary_part(session, 0, 8)
    des_response(hash8, ntlm_hash21(password))
  end

  defp des_response(challenge, hash21) do
    encrypt_des(binary_part(hash21, 0, 7), challenge) <>
      encrypt_des(binary_part(hash21, 7, 7), challenge) <>
      encrypt_des(binary_part(hash21, 14, 7), challenge)
  end

  defp encrypt_des(key7, plaintext8) do
    :crypto.crypto_one_time(:des_ecb, des_key(key7), plaintext8, true)
  end

  defp des_key(<<b0, b1, b2, b3, b4, b5, b6>>) do
    <<
      b0,
      bor(b0 <<< 7, b1 >>> 1),
      bor(b1 <<< 6, b2 >>> 2),
      bor(b2 <<< 5, b3 >>> 3),
      bor(b3 <<< 4, b4 >>> 4),
      bor(b4 <<< 3, b5 >>> 5),
      bor(b5 <<< 2, b6 >>> 6),
      b6 <<< 1
    >>
  end

  defp hmac_md5(key, data), do: :crypto.mac(:hmac, :md5, key, data)

  defp utf16le(string) do
    :unicode.characters_to_binary(string, :utf8, {:utf16, :little})
  end

  defp client_nonce, do: :crypto.strong_rand_bytes(8)

  # Go uses UnixNano as a big-endian uint64. Port that, not FILETIME.
  defp ntlm_timestamp do
    System.os_time(:nanosecond)
  end

  defp split_user(domain, username) do
    username = username || ""
    domain = domain || ""

    case String.split(username, "\\", parts: 2) do
      [user_domain, user] -> {user_domain, user}
      [user] -> {domain, user}
    end
  end

  defp binary_part_pad(string, size) do
    binary = String.slice(string, 0, size)
    pad = size - byte_size(binary)
    binary <> :binary.copy(<<0>>, pad)
  end
end
