-module (simple_secrets_primatives).

nonce()->
  crypto:strong_rand_bytes(16).

derive(MasterKey, Role)->
  erlsha2:sha256([MasterKey,Role]).

derive_sender_hmac(MasterKey)->
  derive(MasterKey, <<"simple-crypto/sender-hmac-key">>).

derive_sender_key(MasterKey)->
  derive(MasterKey, <<"simple-crypto/sender-cipher-key">>).

derive_receiver_hmac(MasterKey)->
  derive(MasterKey, <<"simple-crypto/receiver-hmac-key">>).

derive_receiver_key(MasterKey)->
  derive(MasterKey, <<"simple-crypto/receiver-cipher-key">>).

encrypt(Buffer, Key)->
  <<>>.

decrypt(Buffer, Key, IV)->
  <<>>.

identify(Buffer)->
  <<>>.

mac(Buffer, HmacKey)->
  <<>>.

compare(A, B)->
  true.

binify(String)->
  String.

stringify(Buffer)->
  Buffer.

serialize(Object)->
  msgpack:pack(Object).

deserialize(Buffer)->
  msgpack:unpack(Buffer).
