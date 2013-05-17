-module (simple_secrets).

-export ([init/1]).
-export ([pack/2]).
-export ([unpack/2]).

init(Key)->
  [{master, Key},{keyId, simple_secrets_primatives:identify(Key)}].

pack(Data, Packet)->
  Master = proplists:get_value(master, Packet),
  KeyId = proplists:get_value(keyId, Packet),
  Body = build_body(Data),
  Encrypted = encrypt_body(Body, Master),
  BinMsg = authenticate(Encrypted, Master, KeyId),
  simple_secrets_primatives:stringify(BinMsg).

unpack(Websafe, Packet)->
  Master = proplists:get_value(master, Packet),
  KeyId = proplists:get_value(keyId, Packet),
  BinMsg = simple_secrets_primatives:binify(Websafe),
  case verify(BinMsg, Master, KeyId) of
    {error, _} = Error ->
      Error;
    CipherData ->
      Body = decrypt_body(CipherData, Master),
      body_to_data(Body)
  end.

build_body(Data)->
  Nonce = simple_secrets_primatives:nonce(),
  Bindata = simple_secrets_primatives:serialize(Data),
  <<Nonce/binary, Bindata/binary>>.

body_to_data(Body)->
  <<_Nonce:16/binary, Bindata/binary>> = Body,
  {ok, Data} = simple_secrets_primatives:deserialize(Bindata),
  Data.

encrypt_body(Body, Master)->
  Key = simple_secrets_primatives:derive_sender_key(Master),
  simple_secrets_primatives:encrypt(Body, Key).

decrypt_body(CipherData, Master)->
  Key = simple_secrets_primatives:derive_sender_key(Master),
  <<IV:16/binary, Encrypted/binary>> = CipherData,
  simple_secrets_primatives:decrypt(Encrypted, Key, IV).

authenticate(Data, Master, KeyId)->
  HmacKey = simple_secrets_primatives:derive_sender_hmac(Master),
  Auth = <<KeyId/binary, Data/binary>>,
  Mac = simple_secrets_primatives:mac(Auth, HmacKey),
  <<Auth/binary, Mac/binary>>.

verify(Packet, Master, KeyId)->
  <<PacketKeyId:6/binary, _/binary>> = Packet,
  case simple_secrets_primatives:compare(PacketKeyId, KeyId) of
    true ->
      Data = binary:part(Packet,{0, byte_size(Packet)-32}),
      PacketMac = binary:part(Packet,{byte_size(Packet), -32}),
      HmacKey = simple_secrets_primatives:derive_sender_hmac(Master),
      Mac = simple_secrets_primatives:mac(Data, HmacKey),
      case simple_secrets_primatives:compare(PacketMac, Mac) of
        true ->
          <<_:6/binary, Body/binary>> = Data,
          Body;
        _ ->
          {error, mac_mismatch}
      end;
    _ ->
      {error, key_mismatch}
  end.
