-module (simple_secrets_test).

-compile(export_all).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-define (MASTER_KEY, <<"5db273e71341fa342b45311c25f1b33e249381570c3c6325625f1524aa7d7576">>).
-define (OTHER_MASTER_KEY, <<"50f0b9bdd331fa0dac3e86148f92da804d9a710f8e19c1e7c8421c71a2dcd7c0">>).
-define (MESSAGE, {[{<<"u">>,123456},{<<"s">>,[1,2,3,4]}]}).

prop_valid_messages()->
  Sender = simple_secrets:init(?MASTER_KEY),
  ?FORALL(Msg, binary(),
    begin
      EncMessage = simple_secrets:pack(Msg, Sender),
      DecMessage = simple_secrets:unpack(EncMessage, Sender),
      Msg =:= DecMessage
    end).

recover_text_test()->
  Sender = simple_secrets:init(?MASTER_KEY),
  EncMessage = simple_secrets:pack(?MESSAGE, Sender),
  DecMessage = simple_secrets:unpack(EncMessage, Sender),
  ?assertEqual(?MESSAGE, DecMessage).

decrypt_from_nodejs_test()->
  Sender = simple_secrets:init(?MASTER_KEY),
  EncMessage = <<"bBDTl5NK8dmoh79nbNGph_2PiHWqS7pBiGzuANuYV3TBuh2hEHBNk2MsGzjYZzS2xEufJmgww5p9nXwzyuBPQfQ6mejIcpHwinccraqKMw4155--9FI">>,
  DecMessage = simple_secrets:unpack(EncMessage, Sender),
  ?assertEqual(?MESSAGE, DecMessage).

unrecoverable_text_test()->
  Message = <<"this is a secret message">>,
  Sender = simple_secrets:init(?MASTER_KEY),
  Sender2 = simple_secrets:init(?OTHER_MASTER_KEY),
  EncMessage = simple_secrets:pack(Message, Sender),
  DecMessage = simple_secrets:unpack(EncMessage, Sender2),
  ?assertEqual({error, key_mismatch}, DecMessage).

proper_test_() ->
    [{atom_to_list(F),
      fun () -> ?assert(proper:quickcheck(?MODULE:F(), [long_result])) end}
     || {F, 0} <- ?MODULE:module_info(exports), F > 'prop_', F < 'prop`'].
