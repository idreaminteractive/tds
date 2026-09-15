defmodule Tds.NTLMTest do
  use ExUnit.Case, async: true

  alias Tds.NTLM

  test "type1 is NTLMSSP negotiate with OEM domain and workstation" do
    auth = %NTLM{
      domain: "CONTOSO",
      username: "alice",
      password: "secret",
      workstation: "BOX"
    }

    msg = NTLM.type1(auth)
    assert binary_part(msg, 0, 8) == "NTLMSSP\0"
    assert <<_::binary-size(8), 1::little-32, _::binary>> = msg
    assert String.contains?(msg, "CONTOSO")
    assert String.contains?(msg, "BOX")
  end

  test "from_opts splits DOMAIN\\user" do
    auth = NTLM.from_opts(username: "CONTOSO\\alice", password: "x", workstation: "W")
    assert auth.domain == "CONTOSO"
    assert auth.username == "alice"
  end

  test "type3 against a Type2 with target info is NTLMSSP authenticate" do
    auth = %NTLM{
      domain: "CONTOSO",
      username: "alice",
      password: "Password1",
      workstation: "BOX"
    }

    target_info = <<0, 0>>
    info_offset = 48

    type2 =
      <<"NTLMSSP\0", 2::little-32, 0::little-16, 0::little-16, 0::little-32,
        0x00880001::little-32, "CHALLENG", 0::little-64, 2::little-16, 2::little-16,
        info_offset::little-32, target_info::binary>>

    type3 =
      NTLM.type3(auth, type2, nonce: <<1, 2, 3, 4, 5, 6, 7, 8>>, timestamp: 1_700_000_000_000)

    assert binary_part(type3, 0, 8) == "NTLMSSP\0"
    assert <<_::binary-size(8), 3::little-32, _::binary>> = type3
    assert byte_size(type3) > 88
  end
end
