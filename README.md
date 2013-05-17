simple_secrets.erl [![Build Status](https://travis-ci.org/CamShaft/simple_secrets.erl.png?branch=master)](https://travis-ci.org/CamShaft/simple_secrets.erl)
==================

The erlang implementation of a simple, opinionated library for encrypting small packets of data securely. Designed for exchanging tokens among systems written in a variety of programming languages:

* [Node.js](https://github.com/timshadel/simple-secrets)
* [Ruby](https://github.com/timshadel/simple-secrets.rb)
* [Objective-C](https://github.com/timshadel/SimpleSecrets)
* [Java](https://github.com/timshadel/simple-secrets.java)
* [Erlang](https://github.com/CamShaft/simple_secrets.erl)

## Examples

### Basic

Send:

```erlang
% Try `head /dev/urandom | shasum -a 256` to make a decent 256-bit key
MasterKey = <<"64-char-hex">>,

Sender = simple_secrets:init(MasterKey),
Packet = simple_secrets:pack(<<"this is a secret message">>, Sender),

io:format("~p",[Packet]).
% <<"bBDTl5NKdpvMfriRElbbOw0WEsENjbvv7mqK4"...>>
```

Receive:

```erlang
MasterKey = <<"shared-key-hex">>,
Sender = simple_secrets:init(MasterKey),

% Read data from somewhere
Packet = <<"bBDTl5NKdpvMfriRElbbOw0WEsENjbvv7mqK4"...>>
Message = simple_secrets:unpack(Packet, MasterKey),

io:format("~p",[Message]),
% <<"this is a secret message">>
```

## Can you add ...

No. Seriously. But we might replace what we have with what you suggest. We want exactly one, well-worn path. If you have improvements, we want them. If you want alternatives to choose from you should probably keep looking.

## License

MIT.
