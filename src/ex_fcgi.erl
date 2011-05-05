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


-module(ex_fcgi).
-author('Anthony Ramine <nox@dev.extend.eu>').
-behaviour(gen_server).


-type short() :: 0..65535.

-type address() :: string() | atom() | inet:ip_address().
-type port_number() :: short().

-type req_id() :: short().
-type role() :: responder | authorizer | filter.
-type status() :: request_complete | cant_mpx_conn | overloaded | unknown_role.
-type app_status() :: 0..((1 bsl 32) - 1).

-type key() :: iodata().
-type value() :: iodata().
-type param() :: {key(), value()}.

-type server() :: pid() | atom().

-export_type([address/0, port_number/0,
              req_id/0, role/0, status/0, app_status/0,
              key/0, value/0, param/0, server/0]).


-export([connect/3,
         disconnect/1,
         begin_request/3,
         send/3,
         abort_request/2,
         end_request/2]).

-export([start_link/3,
         init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-record(state, {socket :: inet:socket(),
                table :: ets:tid(),
                next_id = 1 :: req_id()}).


-spec connect(atom(), address(), port_number()) -> {ok, pid()}.
%% @doc Connect to a FastCGI server.
connect(Name, Address, Port) ->
  ChildSpec = {Name,
               {ex_fcgi, start_link, [Name, Address, Port]},
               permanent, 5000, worker, [ex_fcgi]},
  supervisor:start_child(ex_fcgi_sup, ChildSpec).

-spec disconnect(server()) -> ok.
%% Close a connection to a FastCGI server.
disconnect(Server) ->
  case supervisor:terminate_child(ex_fcgi_sup, Server) of
    ok -> supervisor:delete_child(ex_fcgi_sup, Server);
    Error -> Error end.

-spec begin_request(server(), role(), [param()]) -> {ok, reference()}.
%% @doc Make a FastCGI request.
begin_request(Server, Role, Params) ->
  gen_server:call(Server, {begin_request, Role, Params}, infinity).

-spec abort_request(server(), reference()) -> ok.
%% @doc Abort a FastCGI request.
abort_request(Server, Ref) ->
  gen_server:cast(Server, {abort, Ref}).

-spec send(server(), reference(), binary()) -> ok.
%% @doc Send data to a given FastCGI request standard input.
send(Server, Ref, Data) ->
  gen_server:call(Server, {send, Ref, Data}, infinity).

-spec end_request(server(), reference()) -> ok.
%% @doc Send EOF to a given FastCGI request standard output.
end_request(Server, Ref) ->
  gen_server:call(Server, {end_request, Ref}, infinity).


-spec start_link(atom(), address(), port_number()) -> {ok, pid()}.
%% @doc Start a new FastCGI client.
%% @private
start_link(Name, Address, Port) ->
  gen_server:start_link({local, Name}, ?MODULE, {Address, Port},
                        [{timeout, infinity}]).


-spec init({address(), port_number()}) ->
            {ok, #state{}} | {stop, {error, file:posix()}}.
%% @private
init({Address, Port}) ->
  case gen_tcp:connect(Address, Port, [binary, {packet, fcgi}]) of
    {ok, Socket} -> {ok, initial_state(Socket)};
    Error = {error, _Reason} -> {stop, Error} end.

-spec handle_call({begin_request, role(), [param()]}, {pid(), reference()},
                  #state{}) ->
                   {reply, {ok, reference()}, #state{}};
                 ({send, reference(), binary()}, term(), #state{}) ->
                   {reply, ok | {error, not_found}, #state{}};
                 ({end_request, reference()}, term(), #state{}) ->
                   {reply, ok | {error, not_found}, #state{}}.
%% @private
handle_call({begin_request, Role, Params}, {Pid, _Tag}, State) ->
  {ReqId, NewState} = next_req_id(State),
  send_packets([{fcgi_begin_request, ReqId, Role, keepalive},
                {fcgi_params, ReqId, ex_fcgi_protocol:encode_params(Params)},
                {fcgi_params, ReqId, <<>>}],
               NewState),
  Ref = erlang:monitor(process, Pid),
  insert({ReqId, Ref, Pid}, NewState),
  {reply, {ok, Ref}, NewState};
handle_call({send, Ref, Data}, _From, State) when byte_size(Data) =/= 0 ->
  handle_send(Ref, Data, State);
handle_call({end_request, Ref}, _From, State) ->
  handle_send(Ref, <<>>, State).

-spec handle_cast({abort_request, reference()}, #state{}) ->
                   {noreply, #state{}}.
%% @private
handle_cast({abort_request, Ref}, State) ->
  erlang:demonitor(Ref),
  do_abort(Ref, State),
  {noreply, State}.

-spec handle_info({tcp, inet:socket(), binary()}, #state{}) ->
                   {noreply, #state{}};
                 ({'EXIT', reference(), process, pid(), term()}, #state{}) ->
                   {noreply, #state{}};
                 ({tcp_closed, inet:socket()}, #state{}) ->
                   {stop, closed, #state{}}.
%% @private
handle_info({tcp, Socket, Data}, State = #state{socket = Socket}) ->
  % lookup before decode?
  Packet = ex_fcgi_protocol:decode(Data),
  case lookup(ex_fcgi_protocol:req_id(Packet), State) of
    [] -> ok;
    [{_ReqId, Ref, Pid}] -> send_packet_msg(Packet, Ref, Pid, State) end,
  {noreply, State};
handle_info({'EXIT', Ref, process, _Pid, _Reason}, State) ->
  do_abort(Ref, State),
  {noreply, State};
handle_info({tcp_closed, Socket}, State = #state{socket = Socket}) ->
  {stop, closed, State};
handle_info(_Info, State) ->
  {noreply, State}.

-spec terminate(term(), #state{}) -> ok.
%% @private
terminate(_Reason, _State) ->
  ok.

-spec code_change(term(), #state{}, term()) -> {ok, #state{}}.
%% @private
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.


-spec handle_send(reference(), binary(), #state{}) ->
                       {reply, ok | {error, not_found}, #state{}}.
handle_send(Ref, Data, State) ->
  case lookup(Ref, State) of
    [{Ref, ReqId}] ->
      send({fcgi_stdin, ReqId, Data}, State),
      {reply, ok, State};
    [] -> {reply, {error, not_found}, State} end.

-spec send_packet_msg(ex_fcgi_protocol:packet(),
                      reference(), pid(), #state{}) -> ok.
send_packet_msg({fcgi_end_request, _ReqId, Status, AppStatus},
                Ref, Pid, State) ->
  Pid ! {fcgi_end_request, Ref, Status, AppStatus},
  _ = delete(Ref, State),
  ok;
send_packet_msg({fcgi_stdout, _ReqId, Data}, Ref, Pid, _State) ->
  Pid ! {fcgi_stdout, Ref, stream_body(Data)},
  ok;
send_packet_msg({fcgi_stderr, _ReqId, Data}, Ref, Pid, _State) ->
  Pid ! {fcgi_stderr, Ref, stream_body(Data)},
  ok;
send_packet_msg({fcgi_data, _ReqId, Data}, Ref, Pid, _State) ->
  Pid ! {fcgi_data, Ref, stream_body(Data)},
  ok.

-spec stream_body(binary()) -> binary() | eof.
stream_body(<<>>) ->
  eof;
stream_body(Bin) ->
  Bin.


-spec do_abort(reference(), #state{}) -> ok.
do_abort(Ref, State) ->
  case delete(Ref, State) of
    {deleted, ReqId} -> send({fcgi_abort_request, ReqId}, State);
    not_found -> ok end.


-spec initial_state(inet:socket()) -> #state{}.
initial_state(Socket) ->
  #state{socket = Socket, table = ets:new(?MODULE, [private])}.

-spec next_req_id(#state{}) -> {req_id(), #state{}}.
next_req_id(State = #state{next_id = ReqId}) ->
  {ReqId, State#state{next_id = ReqId + 1 rem 65535}}.

-spec send_packets([ex_fcgi_protocol:packet()], #state{}) -> ok.
send_packets(Packets, #state{socket = Socket}) ->
  gen_tcp:send(Socket, [ ex_fcgi_protocol:encode(P) || P <- Packets ]).

-spec send(ex_fcgi_protocol:packet(), #state{}) -> ok.
send(Packet, #state{socket = Socket}) ->
  gen_tcp:send(Socket, ex_fcgi_protocol:encode(Packet)).

-spec insert({req_id(), reference(), pid()}, #state{}) -> true.
insert(Req = {ReqId, Ref, _Pid}, #state{table = Tid}) ->
  true = ets:insert_new(Tid, [Req, {Ref, ReqId}]).

-spec delete(reference(), #state{}) -> {deleted, req_id()} | not_found.
delete(Ref, State = #state{table = Tid}) ->
  case lookup(Ref, State) of
    [{Ref, ReqId}] ->
      ets:delete(Tid, Ref),
      ets:delete(Tid, ReqId),
      {deleted, ReqId};
    [] -> not_found end.

-spec lookup(reference(), #state{}) -> [{reference(), req_id()}];
            (req_id(), #state{}) -> [{req_id(), reference(), pid()}].
lookup(Key, #state{table = Tid}) ->
  ets:lookup(Tid, Key).
