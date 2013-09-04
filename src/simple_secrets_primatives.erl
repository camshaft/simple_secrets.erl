-module (simple_secrets_primatives).

-export ([nonce/0]).
-export ([derive/2]).
-export ([derive_sender_hmac/1]).
-export ([derive_sender_key/1]).
-export ([derive_receiver_hmac/1]).
-export ([derive_receiver_key/1]).
-export ([encrypt/2]).
-export ([decrypt/3]).
-export ([identify/1]).
-export ([mac/2]).
-export ([compare/2]).
-export ([binify/1]).
-export ([stringify/1]).
-export ([serialize/1]).
-export ([deserialize/1]).

nonce()->
  crypto:strong_rand_bytes(16).

derive(MasterKey, Role)->
  crypto:hash(sha256, [MasterKey,Role]).

derive_sender_hmac(MasterKey)->
  derive(MasterKey, <<"simple-crypto/sender-hmac-key">>).

derive_sender_key(MasterKey)->
  derive(MasterKey, <<"simple-crypto/sender-cipher-key">>).

derive_receiver_hmac(MasterKey)->
  derive(MasterKey, <<"simple-crypto/receiver-hmac-key">>).

derive_receiver_key(MasterKey)->
  derive(MasterKey, <<"simple-crypto/receiver-cipher-key">>).

encrypt(Buffer, Key)->
  IV = nonce(),
  Cipher = crypto:block_encrypt(aes_cbc256, Key, IV, pkcs7:pad(Buffer)),
  <<IV/binary, Cipher/binary>>.

decrypt(Buffer, Key, IV)->
  pkcs7:unpad(crypto:block_decrypt(aes_cbc256, Key, IV, Buffer)).

identify(Buffer)->
  Hash = crypto:hash(sha256, [<<(byte_size(Buffer))>>, Buffer]),
  binary:part(Hash, {0, 6}).

mac(Buffer, HmacKey)->
  crypto:hmac(sha256, HmacKey, Buffer).

compare(A, A)->
  true;
compare(_, _)->
  false.

binify(String)->
  base64:decode(websafe_decode(String)).

stringify(Buffer)->
  websafe_encode(base64:encode(Buffer)).

serialize(Object)->
  msgpack:pack(Object).

deserialize(Buffer)->
  case msgpack:unpack(Buffer) of
    {ok, Data} -> Data;
    Error -> Error
  end.

websafe_encode(Buffer)->
  << <<(websafe_encode_char(B))/binary>> || <<B>> <= Buffer >>.

websafe_encode_char($=) -> <<>>;
websafe_encode_char($+) -> <<"-">>;
websafe_encode_char($/) -> <<"_">>;
websafe_encode_char(C) -> <<C>>.

websafe_decode(Buffer)->
  pad(<< <<(websafe_decode_char(B))/binary>> || <<B>> <= Buffer >>).

websafe_decode_char($-) -> <<"+">>;
websafe_decode_char($_) -> <<"/">>;
websafe_decode_char(C) -> <<C>>.

pad(Buffer)->
  case byte_size(Buffer) rem 4 of
    0 -> Buffer;
    Diff -> pad(Buffer, 4-Diff)
  end.

pad(Buffer, 0)->
  Buffer;
pad(Buffer, 1)->
  <<Buffer/binary,"=">>;
pad(Buffer, 2)->
  <<Buffer/binary,"==">>;
pad(Buffer, 3)->
  <<Buffer/binary,"===">>.
