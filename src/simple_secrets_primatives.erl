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
  Cipher = crypto:aes_ctr_encrypt(Key, IV, Buffer),
  <<IV/binary, Cipher/binary>>.

decrypt(Buffer, Key, IV)->
  crypto:aes_ctr_decrypt(Key, IV, Buffer).

identify(Buffer)->
  Length = byte_size(Buffer),
  Hash = <<Length, Buffer/binary>>,
  binary:part(Hash, {0, 6}).

mac(Buffer, HmacKey)->
  crypto:hmac(sha256, HmacKey, Buffer).

compare(A, A)->
  true;
compare(_, _)->
  false.

binify(String)->
  base64:decode(String).

stringify(Buffer)->
  base64:encode(Buffer).

serialize(Object)->
  msgpack:pack(Object).

deserialize(Buffer)->
  msgpack:unpack(Buffer).
