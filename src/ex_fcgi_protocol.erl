%% Copyright (c) 2011, Anthony Ramine <nox@dev-extend.eu>
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


%% @private

-module(ex_fcgi_protocol).
-author('Anthony Ramine <nox@dev.extend.eu>').
-include("constants.hrl").


-type packet_type() :: ?FCGI_BEGIN_REQUEST..?FCGI_UNKNOWN_TYPE.
-type connection_mode() :: keepalive | close.

-type packet() :: {fcgi_begin_request,
                   ex_fcgi:req_id(), ex_fcgi:role(), connection_mode()}
                | {fcgi_end_request,
                   ex_fcgi:req_id(), ex_fcgi:status(), ex_fcgi:app_status()}
                | {fcgi_abort_request, ex_fcgi:req_id()}
                | {fcgi_params, ex_fcgi:req_id(), iodata()}
                | {fcgi_stdin, ex_fcgi:req_id(), iodata()}
                | {fcgi_stdout, ex_fcgi:req_id(), iodata()}
                | {fcgi_stderr, ex_fcgi:req_id(), iodata()}
                | {fcgi_data, ex_fcgi:req_id(), iodata()}
                | {fcgi_get_values, ex_fcgi:req_id(), iodata()}
                | {fcgi_get_values_result, ex_fcgi:req_id(), iodata()}
                | {fcgi_unknown_type, ex_fcgi:req_id()}.

-export_type([packet/0]).


-export([req_id/1,
         decode/1,
         encode/1, encode_params/1]).


-spec req_id(packet()) -> ex_fcgi:req_id().
req_id(Packet) ->
  element(2, Packet).

-spec decode(binary()) -> {packet(), binary()} | more.
%% @doc Decode a FastCGI packet.
decode(Buffer) ->
  case erlang:decode_packet(fcgi, Buffer, []) of
    {ok, <<1, Type, ReqId:16, ContentLength:16, _PaddingLength, _Reserved,
           Content:ContentLength/binary>>, Rest} ->
      {decode(Content, Type, ReqId), Rest};
    {more, _More} ->
      more end.

-spec decode(binary(), packet_type(), ex_fcgi:req_id()) -> packet().
decode(<<RoleInt:16, Flags, _Reserved:40>>, ?FCGI_BEGIN_REQUEST, ReqId) ->
  Role = int_to_role(RoleInt),
  ConnectionMode = flags_to_connection_mode(Flags),
  {fcgi_begin_request, ReqId, Role, ConnectionMode};
decode(<<AppStatus:32, StatusInt, _Reserved:24>>, ?FCGI_END_REQUEST, ReqId) ->
  Status = int_to_status(StatusInt),
  {fcgi_end_request, ReqId, Status, AppStatus};
decode(<<>>, ?FCGI_ABORT_REQUEST, ReqId) ->
  {fcgi_abort_request, ReqId};
decode(<<>>, ?FCGI_UNKNOWN_TYPE, ReqId) ->
  {fcgi_unknown_type, ReqId};
decode(Data, ?FCGI_PARAMS, ReqId) ->
  {fcgi_params, ReqId, Data};
decode(Data, ?FCGI_STDIN, ReqId) ->
  {fcgi_stdin, ReqId, Data};
decode(Data, ?FCGI_STDOUT, ReqId) ->
  {fcgi_stdout, ReqId, Data};
decode(Data, ?FCGI_STDERR, ReqId) ->
  {fcgi_stderr, ReqId, Data};
decode(Data, ?FCGI_DATA, ReqId) ->
  {fcgi_data, ReqId, Data};
decode(Data, ?FCGI_GET_VALUES, ReqId) ->
  {fcgi_get_values, ReqId, Data};
decode(Data, ?FCGI_GET_VALUES_RESULT, ReqId) ->
  {fcgi_get_values_result, ReqId, Data}.

-spec encode(ex_fcgi:packet()) -> iolist().
%% Encode a FastCGI packet.
encode({fcgi_begin_request, ReqId, Role, ConnectionMode}) ->
  RoleInt = role_to_int(Role),
  Flags = connection_mode_to_flags(ConnectionMode),
  wrap(?FCGI_BEGIN_REQUEST, ReqId, <<RoleInt:16, Flags, 0:40>>);
encode({fcgi_abort_request, ReqId}) ->
  wrap(?FCGI_ABORT_REQUEST, ReqId, <<>>);
encode({fcgi_end_request, ReqId, Status, AppStatus}) ->
  StatusInt = status_to_int(Status),
  wrap(?FCGI_END_REQUEST, ReqId, <<AppStatus:32, StatusInt>>);
encode({fcgi_params, ReqId, Data}) ->
  wrap(?FCGI_PARAMS, ReqId, Data);
encode({fcgi_stdin, ReqId, Data}) ->
  wrap(?FCGI_STDIN, ReqId, Data);
encode({fcgi_stdout, ReqId, Data}) ->
  wrap(?FCGI_STDOUT, ReqId, Data);
encode({fcgi_stderr, ReqId, Data}) ->
  wrap(?FCGI_STDERR, ReqId, Data);
encode({fcgi_data, ReqId, Data}) ->
  wrap(?FCGI_DATA, ReqId, Data);
encode({fcgi_get_values, ReqId, Data}) ->
  wrap(?FCGI_GET_VALUES, ReqId, Data);
encode({fcgi_get_values_result, ReqId, Data}) ->
  wrap(?FCGI_GET_VALUES_RESULT, ReqId, Data);
encode({fcgi_unknown_type, ReqId}) ->
  wrap(?FCGI_UNKNOWN_TYPE, ReqId, <<>>).

-spec encode_params([ex_fcgi:param()]) -> [iolist()] | error.
encode_params(Params) ->
  encode_params(Params, [<<>>], [], 0, []).

-spec encode_params([ex_fcgi:param() | {encoded, ex_fcgi:short(), iolist()}],
                    [iodata()], [iodata()], ex_fcgi:short(),
                    [{encoded, ex_fcgi:short(), iolist()}]) ->
                      [iodata()] | error.
encode_params([P = {_N, _V} | Ps], Packets, Acc, L, Skipped) ->
  E = {encoded, Size, _IoList} = encode_param(P),
  case Size > 65535 of
    true ->
      % The param is too big to be put in a single FastCGI packet; as no
      % known implementation supports the params-as-stream feature, this is
      % considered an error.
      error;
    false ->
      encode_params(Ps, Packets, Acc, L, Skipped, E) end;
encode_params([E | Ps], Packets, Acc, L, Skipped) ->
  encode_params(Ps, Packets, Acc, L, Skipped, E);
encode_params([], Packets, Acc, _L, []) ->
  [Acc|Packets];
encode_params([], _Packets, [], 0, _Skipped) ->
  error;
encode_params([], Packets, Acc, _L, Skipped) ->
  encode_params(Skipped, [Acc|Packets], [], 0, []).

-spec encode_params([ex_fcgi:param() | {encoded, ex_fcgi:short(), iolist()}],
                    [iodata()], [iodata()], ex_fcgi:short(),
                    [{encoded, ex_fcgi:short(), iolist()}],
                    {encoded, non_neg_integer(), iolist()}) ->
                      [iodata()] | error.
encode_params(Rest, Packets, Acc, L, Skipped, E = {encoded, Size, IoList}) ->
  NewLength = Size + L,
  case NewLength > 65535 of
    true ->
      % This param is too big to be put in the remaining space of the
      % current FastCGI packet; put its encoded form in the skipped stack.
      encode_params(Rest, Packets, Acc, L, [E | Skipped]);
    false ->
      encode_params(Rest, Packets, [IoList | Acc], NewLength, Skipped) end.

-spec encode_param(ex_fcgi:param()) -> {encoded, non_neg_integer(), iolist()}.
encode_param({N, V}) ->
  NLen = iolist_size(N),
  VLen = iolist_size(V),
  Size = NLen + VLen,
  if NLen =< 127, VLen =< 127 ->
       {encoded, Size + 2, [<<0:1, NLen:7, 0:1, VLen:7>>, N, V]};
     NLen =< 127 ->
       {encoded, Size + 5, [<<0:1, NLen:7, 1:1, VLen:31>>, N, V]};
     VLen =< 127 ->
       {encoded, Size + 5, [<<1:1, NLen:31, 0:1, VLen:7>>, N, V]};
     true ->
       {encoded, Size + 8, [<<1:1, NLen:31, 1:1, VLen:31>>, N, V]} end.

-spec wrap(packet_type(), ex_fcgi:req_id(), iodata()) -> iolist().
wrap(Type, ReqId, Content) ->
  [<<1, Type, ReqId:16, (iolist_size(Content)):16, 0, 0>>] ++ Content.

-spec int_to_role(?FCGI_RESPONDER) -> responder;
                 (?FCGI_AUTHORIZER) -> authorizer;
                 (?FCGI_FILTER) -> filter.
int_to_role(?FCGI_RESPONDER) ->
  responder;
int_to_role(?FCGI_AUTHORIZER) ->
  authorizer;
int_to_role(?FCGI_FILTER) ->
  filter.

-spec role_to_int(responder) -> ?FCGI_RESPONDER;
                 (authorizer) -> ?FCGI_AUTHORIZER;
                 (filter) -> ?FCGI_FILTER.
role_to_int(responder) ->
  ?FCGI_RESPONDER;
role_to_int(authorizer) ->
  ?FCGI_AUTHORIZER;
role_to_int(filter) ->
  ?FCGI_FILTER.

-spec flags_to_connection_mode(byte()) -> ex_fcgi:connection_mode().
flags_to_connection_mode(Flags) when Flags band (bnot ?FCGI_KEEP_CONN) =:= 0 ->
  case Flags band ?FCGI_KEEP_CONN =/= 0 of
    true -> keepalive;
    false -> close end.

-spec connection_mode_to_flags(keepalive) -> ?FCGI_KEEP_CONN;
                              (close) -> 0.
connection_mode_to_flags(keepalive) ->
  ?FCGI_KEEP_CONN;
connection_mode_to_flags(close) ->
  0.

-spec int_to_status(?FCGI_REQUEST_COMPLETE) -> request_complete;
                   (?FCGI_CANT_MPX_CONN) -> cant_mpx_conn;
                   (?FCGI_OVERLOADED) -> overloaded;
                   (?FCGI_UNKNOWN_ROLE) -> unknown_role.
int_to_status(?FCGI_REQUEST_COMPLETE) ->
  request_complete;
int_to_status(?FCGI_CANT_MPX_CONN) ->
  cant_mpx_conn;
int_to_status(?FCGI_OVERLOADED) ->
  overloaded;
int_to_status(?FCGI_UNKNOWN_ROLE) ->
  unknown_role.

-spec status_to_int(request_complete) -> ?FCGI_REQUEST_COMPLETE;
                   (cant_mpx_conn) -> ?FCGI_CANT_MPX_CONN;
                   (overloaded) -> ?FCGI_OVERLOADED;
                   (unknown_role) -> ?FCGI_UNKNOWN_ROLE.
status_to_int(request_complete) ->
  ?FCGI_REQUEST_COMPLETE;
status_to_int(cant_mpx_conn) ->
  ?FCGI_CANT_MPX_CONN;
status_to_int(overloaded) ->
  ?FCGI_OVERLOADED;
status_to_int(unknown_role) ->
  ?FCGI_UNKNOWN_ROLE.
