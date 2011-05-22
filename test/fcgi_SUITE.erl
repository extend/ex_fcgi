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


-module(fcgi_SUITE).
-author('Anthony Ramine <nox@dev.extend.eu>').
-include_lib("ex_fcgi/src/constants.hrl").


-export([all/0, init_per_suite/1, end_per_suite/1]).

-export([big_param/1,
         timeout/1,
         simple_request/1,
         multiplex/1,
         unknown_packet/1,
         abort_request/1,
         send/1,
         kill/1,
         stream/1]).


all() ->
  [big_param, simple_request, timeout, multiplex, unknown_packet,
   abort_request, send, kill, stream].

init_per_suite(Config) ->
  application:start(ex_fcgi),
  Config.

end_per_suite(_Config) ->
  application:stop(sasl),
  ok.

big_param(_Config) ->
  DeadPid = spawn(fun () -> ok end),
  Params = [{<<"I_AM_BIG">>, <<0:65535/unit:8>>}],
  error = ex_fcgi:begin_request(DeadPid, responder, Params, 0).

simple_request(_Config) ->
  Options = [binary, {active, false}, {reuseaddr, true}],
  {ok, LSocket} = gen_tcp:listen(33000, Options),
  {ok, _Pid} = ex_fcgi:start(fcgi, localhost, 33000),
  try
    Params = [{<<"NAME">>, <<"VALUE">>}],
    {ok, Ref} = ex_fcgi:begin_request(fcgi, responder, Params, 3000),
    {ok, Socket} = gen_tcp:accept(LSocket, 1000),
    try
      {ok, Data} = gen_tcp:recv(Socket, 43, 1000),
      <<% {begin_request, ReqId, responder, [keepalive]}
        1, ?FCGI_BEGIN_REQUEST, ReqId:16, 8:16, 0, _, ?FCGI_RESPONDER:16,
        ?FCGI_KEEP_CONN, _:40,
        % {params, ReqId, [<<"NAME">>, <<"VALUE">>]}
        1, ?FCGI_PARAMS, ReqId:16, 11:16, 0, _,
        0:1, 4:7, 0:1, 5:7, "NAME", "VALUE",
        % {params, ReqId, eof}
        1, ?FCGI_PARAMS, ReqId:16, 0:16, 0, _>> = Data,
      Reply = <<% {stdout, ReqId, <<"This is a boring test response.">>}
                1, ?FCGI_STDOUT, ReqId:16, 31:16, 0, 0,
                "This is a boring test response.",
                % {stdout, ReqId, eof}
                1, ?FCGI_STDOUT, ReqId:16, 0:16, 0, 0,
                % {end_request, ReqId, request_complete, 42}
                1, ?FCGI_END_REQUEST, ReqId:16, 8:16, 0, 0,
                42:32, ?FCGI_REQUEST_COMPLETE, 0:24>>,
      ok = gen_tcp:send(Socket, Reply),
      receive
        {ex_fcgi, Ref, Messages} ->
          [{stdout, <<"This is a boring test response.">>},
           {stdout, eof},
           {end_request, request_complete, 42}] = Messages;
        {ex_fcgi_timeout, Ref} ->
          exit(got_timeout)
      after 2000 ->
        exit(got_nothing) end
    after
      gen_tcp:close(Socket) end
  after
    ex_fcgi:stop(fcgi),
    gen_tcp:close(LSocket) end.

timeout(_Config) ->
  DeadPid = spawn(fun () -> ok end),
  {ok, Ref} = ex_fcgi:begin_request(DeadPid, responder, [{<<"P">>, <<"">>}], 0),
  receive
    {ex_fcgi_timeout, Ref} ->
      ok
  after 1000 ->
    throw(fail) end.

multiplex(_Config) ->
  Options = [binary, {active, false}, {reuseaddr, true}],
  {ok, LSocket} = gen_tcp:listen(33000, Options),
  {ok, _Pid} = ex_fcgi:start(fcgi, localhost, 33000),
  try
    {ok, Ref1} = ex_fcgi:begin_request(fcgi, responder,
                                       [{<<"N">>, <<"1">>}], 3000),
    {ok, Socket} = gen_tcp:accept(LSocket, 1000),
    try
      {ok, Ref2} = ex_fcgi:begin_request(fcgi, responder,
                                         [{<<"N">>, <<"2">>}], 3000),
      {ok, Data} = gen_tcp:recv(Socket, 72, 1000),
      <<% {begin_request, ReqId1, responder, [keepalive]}
        1, ?FCGI_BEGIN_REQUEST, ReqId1:16, 8:16, 0, _, ?FCGI_RESPONDER:16,
        ?FCGI_KEEP_CONN, _:40,
        % {params, ReqId1, [<<"N">>, <<"1">>]}
        1, ?FCGI_PARAMS, ReqId1:16, 4:16, 0, _,
        0:1, 1:7, 0:1, 1:7, "N", "1",
        % {params, ReqId1, eof}
        1, ?FCGI_PARAMS, ReqId1:16, 0:16, 0, _,
        % {begin_request, ReqId2, responder, [keepalive]}
        1, ?FCGI_BEGIN_REQUEST, ReqId2:16, 8:16, 0, _, ?FCGI_RESPONDER:16,
        ?FCGI_KEEP_CONN, _:40,
        % {params, ReqId2, [<<"N">>, <<"2">>]}
        1, ?FCGI_PARAMS, ReqId2:16, 4:16, 0, _,
        0:1, 1:7, 0:1, 1:7, "N", "2",
        % {params, ReqId2, eof}
        1, ?FCGI_PARAMS, ReqId2:16, 0:16, 0, _>> = Data,
      Reply = <<% {end_request, ReqId2, request_complete, 42}
                1, ?FCGI_END_REQUEST, ReqId2:16, 8:16, 0, 0,
                2:32, ?FCGI_REQUEST_COMPLETE, 0:24,
                % {end_request, ReqId1, request_complete, 42}
                1, ?FCGI_END_REQUEST, ReqId1:16, 8:16, 0, 0,
                1:32, ?FCGI_REQUEST_COMPLETE, 0:24>>,
      ok = gen_tcp:send(Socket, Reply),
      receive
        {ex_fcgi, Ref2, Messages2} ->
          [{end_request, request_complete, 2}] = Messages2,
          receive
            {ex_fcgi, Ref1, Messages1} ->
              [{end_request, request_complete, 1}] = Messages1;
            {ex_fcgi_timeout, Ref1} ->
              exit(got_timeout_1)
          after 2000 ->
            exit(got_nothing_1) end;
        {ex_fcgi_timeout, Ref2} ->
          exit(got_timeout_2)
      after 2000 ->
        exit(got_nothing_2) end
    after
      gen_tcp:close(Socket) end
  after
    ex_fcgi:stop(fcgi),
    gen_tcp:close(LSocket) end.

unknown_packet(_Config) ->
  Options = [binary, {active, false}, {reuseaddr, true}],
  {ok, LSocket} = gen_tcp:listen(33000, Options),
  {ok, _Pid} = ex_fcgi:start(fcgi, localhost, 33000),
  try
    Params = [{<<"P">>, <<"">>}],
    {ok, Ref} = ex_fcgi:begin_request(fcgi, responder, Params, 3000),
    {ok, Socket} = gen_tcp:accept(LSocket, 1000),
    try
      {ok, Data} = gen_tcp:recv(Socket, 35, 1000),
      <<% {begin_request, ReqId, responder, [keepalive]}
        1, ?FCGI_BEGIN_REQUEST, ReqId:16, 8:16, 0, _, ?FCGI_RESPONDER:16,
        ?FCGI_KEEP_CONN, _:40,
        % {params, ReqId, [<<"P">>, <<"">>]}
        1, ?FCGI_PARAMS, ReqId:16, 3:16, 0, _,
        0:1, 1:7, 0:1, 0:7, "P", "",
        % {params, ReqId, eof}
        1, ?FCGI_PARAMS, ReqId:16, 0:16, 0, _>> = Data,
      Reply = <<% {end_request, ReqId + 1, request_complete, 42}
                1, ?FCGI_END_REQUEST, (ReqId + 1):16, 8:16, 0, 0,
                42:32, ?FCGI_REQUEST_COMPLETE, 0:24,
                % {end_request, ReqId, request_complete, 0}
                1, ?FCGI_END_REQUEST, ReqId:16, 8:16, 0, 0,
                0:32, ?FCGI_REQUEST_COMPLETE, 0:24>>,
      ok = gen_tcp:send(Socket, Reply),
      receive
        {ex_fcgi, Ref, Messages} ->
          [{end_request, request_complete, 0}] = Messages;
        {ex_fcgi_timeout, Ref} ->
          exit(got_timeout)
      after 2000 ->
        exit(got_nothing) end
    after
      gen_tcp:close(Socket) end
  after
    ex_fcgi:stop(fcgi),
    gen_tcp:close(LSocket) end.

abort_request(_Config) ->
  Options = [binary, {active, false}, {reuseaddr, true}],
  {ok, LSocket} = gen_tcp:listen(33000, Options),
  {ok, _Pid} = ex_fcgi:start(fcgi, localhost, 33000),
  try
    Params = [{<<"P">>, <<"">>}],
    {ok, Ref} = ex_fcgi:begin_request(fcgi, responder, Params, 500),
    {ok, Socket} = gen_tcp:accept(LSocket, 500),
    try
      ex_fcgi:abort_request(fcgi, Ref),
      {ok, Data} = gen_tcp:recv(Socket, 43, 500),
      <<% {begin_request, ReqId, responder, [keepalive]}
        1, ?FCGI_BEGIN_REQUEST, ReqId:16, 8:16, 0, _, ?FCGI_RESPONDER:16,
        ?FCGI_KEEP_CONN, _:40,
        % {params, ReqId, [<<"P">>, <<"">>]}
        1, ?FCGI_PARAMS, ReqId:16, 3:16, 0, _,
        0:1, 1:7, 0:1, 0:7, "P", "",
        % {params, ReqId, eof}
        1, ?FCGI_PARAMS, ReqId:16, 0:16, 0, _,
        % {abort_request, ReqId}
        1, ?FCGI_ABORT_REQUEST, ReqId:16, 0:16, 0, _>> = Data,
      receive
        {ex_fcgi, Ref, _Messages} ->
          exit(got_messages);
        {ex_fcgi_timeout, Ref} ->
          exit(got_timeout)
      after 600 ->
        ok end
    after
      gen_tcp:close(Socket) end
  after
    ex_fcgi:stop(fcgi),
    gen_tcp:close(LSocket) end.

send(_Config) ->
  Options = [binary, {active, false}, {reuseaddr, true}],
  {ok, LSocket} = gen_tcp:listen(33000, Options),
  {ok, _Pid} = ex_fcgi:start(fcgi, localhost, 33000),
  try
    Params = [{<<"P">>, <<"">>}],
    {ok, Ref} = ex_fcgi:begin_request(fcgi, responder, Params, 500),
    {ok, Socket} = gen_tcp:accept(LSocket, 500),
    try
      ex_fcgi:send(fcgi, Ref, <<"Request body.">>),
      ex_fcgi:end_request(fcgi, Ref),
      {ok, Data} = gen_tcp:recv(Socket, 64, 500),
      <<% {begin_request, ReqId, responder, [keepalive]}
        1, ?FCGI_BEGIN_REQUEST, ReqId:16, 8:16, 0, _, ?FCGI_RESPONDER:16,
        ?FCGI_KEEP_CONN, _:40,
        % {params, ReqId, [<<"P">>, <<"">>]}
        1, ?FCGI_PARAMS, ReqId:16, 3:16, 0, _,
        0:1, 1:7, 0:1, 0:7, "P", "",
        % {params, ReqId, eof}
        1, ?FCGI_PARAMS, ReqId:16, 0:16, 0, _,
        % {stdin, ReqId, <<"Request body.">>}
        1, ?FCGI_STDIN, ReqId:16, 13:16, 0, _, "Request body.",
        %, {stdin, ReqId, <<>>}
        1, ?FCGI_STDIN, ReqId:16, 0:16, 0, _>> = Data,
      Reply = <<% {end_request, ReqId, request_complete, 0}
                1, ?FCGI_END_REQUEST, ReqId:16, 8:16, 0, 0,
                0:32, ?FCGI_REQUEST_COMPLETE, 0:24>>,
      ok = gen_tcp:send(Socket, Reply),
      receive
        {ex_fcgi, Ref, Messages} ->
          [{end_request, request_complete, 0}] = Messages;
        {ex_fcgi_timeout, Ref} ->
          exit(got_timeout)
      after 2000 ->
        exit(got_nothing) end
    after
      gen_tcp:close(Socket) end
  after
    ex_fcgi:stop(fcgi),
    gen_tcp:close(LSocket) end.

kill(_Config) ->
  Options = [binary, {active, false}, {reuseaddr, true}],
  {ok, LSocket} = gen_tcp:listen(33000, Options),
  {ok, _FCGIPid} = ex_fcgi:start(fcgi, localhost, 33000),
  try
    Params = [{<<"P">>, <<"">>}],
    F = fun () ->
          {ok, _Ref} = ex_fcgi:begin_request(fcgi, responder, Params, 500),
          receive
            stop -> ok end end,
    Pid = spawn_link(F),
    {ok, Socket} = gen_tcp:accept(LSocket, 500),
    try
      Pid ! stop,
      {ok, Data} = gen_tcp:recv(Socket, 43, 500),
      <<% {begin_request, ReqId, responder, [keepalive]}
        1, ?FCGI_BEGIN_REQUEST, ReqId:16, 8:16, 0, _, ?FCGI_RESPONDER:16,
        ?FCGI_KEEP_CONN, _:40,
        % {params, ReqId, [<<"P">>, <<"">>]}
        1, ?FCGI_PARAMS, ReqId:16, 3:16, 0, _,
        0:1, 1:7, 0:1, 0:7, "P", "",
        % {params, ReqId, eof}
        1, ?FCGI_PARAMS, ReqId:16, 0:16, 0, _,
        % {abort_request, ReqId}
        1, ?FCGI_ABORT_REQUEST, ReqId:16, 0:16, 0, _>> = Data
    after
      gen_tcp:close(Socket) end
  after
    ex_fcgi:stop(fcgi),
    gen_tcp:close(LSocket) end.

stream(_Config) ->
  Options = [binary, {active, false}, {reuseaddr, true}],
  {ok, LSocket} = gen_tcp:listen(33000, Options),
  {ok, _Pid} = ex_fcgi:start(fcgi, localhost, 33000),
  try
    Params = [{<<"P">>, <<"">>}],
    {ok, Ref} = ex_fcgi:begin_request(fcgi, responder, Params, 3000),
    {ok, Socket} = gen_tcp:accept(LSocket, 1000),
    try
      {ok, Data} = gen_tcp:recv(Socket, 35, 1000),
      <<% {begin_request, ReqId, responder, [keepalive]}
        1, ?FCGI_BEGIN_REQUEST, ReqId:16, 8:16, 0, _, ?FCGI_RESPONDER:16,
        ?FCGI_KEEP_CONN, _:40,
        % {params, ReqId, [<<"P">>, <<"">>]}
        1, ?FCGI_PARAMS, ReqId:16, 3:16, 0, _,
        0:1, 1:7, 0:1, 0:7, "P", "",
        % {params, ReqId, eof}
        1, ?FCGI_PARAMS, ReqId:16, 0:16, 0, _>> = Data,
      Reply1 = <<% {stdout, ReqId, <<"This is a boring test ">> ...
                 1, ?FCGI_STDOUT, ReqId:16, 31:16, 0, 0,
                 "This is a boring test ">>,
      ok = gen_tcp:send(Socket, Reply1),
      Reply2 = <<% ... <<"response.">>}
                 "response.",
                 % {end_request, ReqId + 1, request_complete, 1337}
                 1, ?FCGI_END_REQUEST, (ReqId + 1):16, 8:16, 0, 0,
                 1337:32, ?FCGI_REQUEST_COMPLETE, 0:24,
                 % {stdout, ReqId, eof}
                 1, ?FCGI_STDOUT, ReqId:16, 0:16, 0, 0,
                 % {end_request, ...
                 1, ?FCGI_END_REQUEST>>,
      ok = gen_tcp:send(Socket, Reply2),
      receive
        {ex_fcgi, Ref, Messages1} ->
          [{stdout, <<"This is a boring test response.">>},
           {stdout, eof}] = Messages1,
          Reply3 = <<% ... ReqId, ...
                     ReqId:16, 8:16, 0, 0>>,
          ok = gen_tcp:send(Socket, Reply3),
          Reply4 = <<% ... request_complete, 42}
                     42:32, ?FCGI_REQUEST_COMPLETE, 0:24>>,
          ok = gen_tcp:send(Socket, Reply4),
          receive
            {ex_fcgi, Ref, Messages2} ->
              [{end_request, request_complete, 42}] = Messages2;
            {ex_fcgi_timeout, Ref} ->
              exit(got_timeout_2)
          after 2000 ->
            exit(got_nothing_2) end;
        {ex_fcgi_timeout, Ref} ->
          exit(got_timeout_1)
      after 2000 ->
        exit(got_nothing_1) end
    after
      gen_tcp:close(Socket) end
  after
    ex_fcgi:stop(fcgi),
    gen_tcp:close(LSocket) end.
