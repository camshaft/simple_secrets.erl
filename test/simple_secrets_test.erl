-module (simple_secrets_test).

-compile(export_all).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-define (MASTER_KEY, <<"12345678901234567890123456789012">>).
-define (OTHER_MASTER_KEY, <<"09876543210987654321098765432109">>).

prop_valid_messages()->
  Sender = simple_secrets:init(?MASTER_KEY),
  ?FORALL(Msg, binary(),
    begin
      EncMessage = simple_secrets:pack(Msg, Sender),
      DecMessage = simple_secrets:unpack(EncMessage, Sender),
      Msg =:= DecMessage
    end).

recover_text_test()->
  Message = <<"this is a secret message">>,
  Sender = simple_secrets:init(?MASTER_KEY),
  EncMessage = simple_secrets:pack(Message, Sender),
  DecMessage = simple_secrets:unpack(EncMessage, Sender),
  ?assertEqual(Message, DecMessage).

unrecoverable_text_test()->
  Message = <<"this is a secret message">>,
  Sender = simple_secrets:init(?MASTER_KEY),
  Sender2 = simple_secrets:init(?OTHER_MASTER_KEY),
  EncMessage = simple_secrets:pack(Message, Sender),
  DecMessage = simple_secrets:unpack(EncMessage, Sender2),
  ?assertEqual(false, DecMessage).

proper_test_() ->
    [{atom_to_list(F),
      fun () -> ?assert(proper:quickcheck(?MODULE:F(), [long_result])) end}
     || {F, 0} <- ?MODULE:module_info(exports), F > 'prop_', F < 'prop`'].
