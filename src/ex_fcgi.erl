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


-type short() :: 0..65535.
-type uint32() :: 0..(1 bsl 32 - 1).

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
         begin_request/4,
         send/3,
         abort_request/2,
         end_request/2]).

-export([start_link/3,
         init/4,
         system_continue/3,
         system_terminate/4,
         system_code_change/4,
         format_status/2]).

-record(state, {parent :: pid(),
                socket :: undefined | inet:socket(),
                address :: address(),
                port :: port_number(),
                requests :: ets:tid(),
                monitors :: ets:tid(),
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

-spec begin_request(server(), role(), [param()], uint32()) -> {ok, reference()}.
%% @doc Make a FastCGI request.
begin_request(Server, Role, Params, Timeout) ->
  Ref = make_ref(),
  Timer = erlang:send_after(Timeout, self(), {fcgi_timeout, Ref}),
  Server ! {ex_fcgi_begin_request, Ref, Timer, self(), Role, Params},
  {ok, Ref}.

-spec abort_request(server(), reference()) -> ok.
%% @doc Abort a FastCGI request.
abort_request(Server, Ref) ->
  Server ! {ex_fcgi_abort_request, Ref},
  ok.

-spec send(server(), reference(), binary()) -> ok.
%% @doc Send data to a given FastCGI request standard input.
send(Server, Ref, Data) ->
  Server ! {ex_fcgi_send, Ref, Data},
  ok.

-spec end_request(server(), reference()) -> ok.
%% @doc Send EOF to a given FastCGI request standard input.
end_request(Server, Ref) ->
  Server ! {ex_fcgi_end_request, Ref},
  ok.


-spec start_link(atom(), address(), port_number()) -> {ok, pid()}.
%% @doc Start a new FastCGI client.
%% @private
start_link(Name, Address, Port) ->
  Pid = proc_lib:spawn_link(?MODULE, init, [Name, self(), Address, Port]),
  {ok, Pid}.


-spec init(atom(), pid(), address(), port_number()) -> no_return().
%% @private
init(Name, Parent, Address, Port) ->
  State = initial_state(Parent, Address, Port),
  register(Name, self()),
  receive_loop(State).

-spec receive_loop(#state{}) -> no_return().
receive_loop(State) ->
  receive Msg -> receive_loop(handle_msg(Msg, State)) end.

-spec system_continue(pid(), term(), #state{}) -> no_return().
%% @private
system_continue(Parent, _Debug, State) ->
  receive_loop(State#state{parent = Parent}).

-spec system_terminate(term(), pid(), [], #state{}) -> no_return().
%% @private
system_terminate(Reason, _Parent, _Debug, _State) ->
  exit(Reason).

-spec system_code_change(#state{}, module(), term(), term()) -> {ok, #state{}}.
%% @private
system_code_change(State, _Module, _OldVsn, _Extra) ->
  {ok, State}.

-spec format_status(atom(), [term()]) -> term().
%% @private
format_status(_Opt, [_PDict, _SysState, Parent, _Debug,
                     #state{socket = Socket, address = Address, port = Port,
                            monitors = Monitors, next_id = NextId}]) ->
  Connected = case Socket of
                undefined -> false;
                _ -> true end,
  [{data, [{"State", [{connected, Connected},
                      {address, Address},
                      {port, Port},
                      {next_id, NextId},
                      {current_reqs_count, ets:info(Monitors, size)}]}]}].

-spec handle_msg(term(), #state{}) -> #state{}.
handle_msg({ex_fcgi_begin_request, Ref, Timer, Pid, Role, Params}, State) ->
  {ReqId, State1} = next_req_id(State),
  State2 = send_packets([{fcgi_begin_request, ReqId, Role, keepalive},
                         {fcgi_params, ReqId,
                          ex_fcgi_protocol:encode_params(Params)},
                         {fcgi_params, ReqId, <<>>}], State1),
  MonitorRef = erlang:monitor(process, Pid),
  insert({ReqId, Ref, Timer, Pid, MonitorRef}, State2),
  State2;
handle_msg({ex_fcgi_send, Ref, Data}, State) ->
  handle_send(Ref, Data, State);
handle_msg({ex_fcgi_end_request, Ref}, State) ->
  handle_send(Ref, <<>>, State);
handle_msg({ex_fcgi_abort_request, Ref}, State) ->
  case lookup(Ref, State) of
    [{_Ref, ReqId}] ->
      [{_ReqId, _Ref, Timer, _Pid, MonitorRef}] = lookup(ReqId, State),
      _ = erlang:cancel_timer(Timer),
      erlang:demonitor(MonitorRef),
      delete_monitor(MonitorRef, State),
      delete(Ref, State),
      delete(ReqId, State),
      do_abort(ReqId, State);
    [] -> State end;
handle_msg({tcp, Socket, Data}, State = #state{socket = Socket}) ->
  Packet = ex_fcgi_protocol:decode(Data),
  case lookup(ex_fcgi_protocol:req_id(Packet), State) of
    [] -> State;
    [Req] -> send_packet_msg(Packet, Req, State) end;
handle_msg({'EXIT', MonitorRef, process, _Pid, _Reason}, State) ->
  case lookup_monitor(MonitorRef, State) of
    [{_MonitorRef, Ref}] ->
      delete_monitor(MonitorRef, State),
      [{_Ref, ReqId}] = lookup(Ref, State),
      delete(Ref, State),
      delete(ReqId, State),
      do_abort(ReqId, State);
    [] -> State end;
handle_msg({tcp_closed, Socket}, State = #state{socket = Socket}) ->
  State#state{socket = undefined};
handle_msg({system, From, Msg}, State = #state{parent = Parent}) ->
  sys:handle_system_msg(Msg, From, Parent, ?MODULE, [], State);
handle_msg(_Msg, State) ->
  State.

handle_send(Ref, Data, State) ->
  case lookup(Ref, State) of
    [{Ref, ReqId}] -> send({fcgi_stdin, ReqId, Data}, State);
    [] -> State end.

-spec send_packet_msg(ex_fcgi_protocol:packet(),
                      {req_id(), Ref::reference(), Timer::reference(), pid(),
                       MonitorRef::reference()}, #state{}) -> #state{}.
send_packet_msg({fcgi_end_request, ReqId, Status, AppStatus},
                {_ReqId, Ref, Timer, Pid, MonitorRef}, State) ->
  Pid ! {fcgi_end_request, Ref, Status, AppStatus},
  _ = erlang:cancel_timer(Timer),
  erlang:demonitor(MonitorRef),
  delete_monitor(MonitorRef, State),
  delete(Ref, State),
  delete(ReqId, State),
  State;
send_packet_msg({fcgi_stdout, _ReqId, Data},
                {_ReqId, Ref, _Timer, Pid, _MonitorRef}, State) ->
  Pid ! {fcgi_stdout, Ref, stream_body(Data)},
  State;
send_packet_msg({fcgi_stderr, _ReqId, Data},
                {_ReqId, Ref, _Timer, Pid, _MonitorRef}, State) ->
  Pid ! {fcgi_stderr, Ref, stream_body(Data)},
  State;
send_packet_msg({fcgi_data, _ReqId, Data},
                {_ReqId, Ref, _Timer, Pid, _MonitorRef}, State) ->
  Pid ! {fcgi_data, Ref, stream_body(Data)},
  State.

-spec stream_body(binary()) -> binary() | eof.
stream_body(<<>>) ->
  eof;
stream_body(Bin) ->
  Bin.


-spec do_abort(req_id(), #state{}) -> #state{}.
do_abort(ReqId, State) ->
  send({fcgi_abort_request, ReqId}, State).


-spec initial_state(pid(), address(), port_number()) -> #state{}.
initial_state(Parent, Address, Port) ->
  #state{parent = Parent, address = Address, port = Port,
         requests = ets:new(requests, [private]),
         monitors = ets:new(monitors, [private])}.

-spec next_req_id(#state{}) -> {req_id(), #state{}}.
next_req_id(State = #state{next_id = ReqId}) ->
  {ReqId, State#state{next_id = ReqId + 1 rem 65535}}.

-spec send_packets([ex_fcgi_protocol:packet()], #state{}) -> #state{}.
send_packets(Packets, State = #state{socket = undefined}) ->
  send_packets(Packets, open_socket(State));
send_packets(Packets, State = #state{socket = Socket}) ->
  ok = gen_tcp:send(Socket, [ ex_fcgi_protocol:encode(P) || P <- Packets ]),
  State.

-spec send(ex_fcgi_protocol:packet(), #state{}) -> #state{}.
send(Packet, State = #state{socket = undefined}) ->
  send(Packet, open_socket(State));
send(Packet, State = #state{socket = Socket}) ->
  ok = gen_tcp:send(Socket, ex_fcgi_protocol:encode(Packet)),
  State.

-spec open_socket(#state{socket :: undefined}) ->
                  #state{socket :: inet:socket()}.
open_socket(State = #state{socket = undefined,
                           address = Address,
                           port = Port}) ->
  {ok, Socket} = gen_tcp:connect(Address, Port, [binary, {packet, fcgi}]),
  State#state{socket = Socket}.

-spec insert({req_id(), Ref::reference(), Timer::reference(), pid(),
              MonitorRef::reference()}, #state{}) -> true.
insert(Req = {ReqId, Ref, _Timer, _Pid, MonitorRef},
       #state{requests = Requests, monitors = Monitors}) ->
  true = ets:insert_new(Requests, [Req, {Ref, ReqId}]),
  true = ets:insert_new(Monitors, [{MonitorRef, Ref}]).

-spec lookup(reference(), #state{}) -> [{reference(), req_id()}];
            (req_id(), #state{}) ->
              [{req_id(), Ref::reference(), Timer::reference(), pid(),
               MonitorRef::reference()}].
lookup(Key, #state{requests = Requests}) ->
  ets:lookup(Requests, Key).

-spec delete(reference() | req_id(), #state{}) -> true.
delete(Key, #state{requests = Requests}) ->
  ets:delete(Requests, Key).

-spec lookup_monitor(reference(), #state{}) ->
                      [{MonitorRef::reference(), Ref::reference()}].
lookup_monitor(MonitorRef, #state{monitors = Monitors}) ->
  ets:lookup(Monitors, MonitorRef).

-spec delete_monitor(reference(), #state{}) -> true.
delete_monitor(MonitorRef, #state{monitors = Monitors}) ->
  ets:delete(Monitors, MonitorRef).
