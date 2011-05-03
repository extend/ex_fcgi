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

-module(ex_fcgi_sup).
-author('Anthony Ramine <nox@dev.extend.eu>').
-behaviour(supervisor).

-export([start_link/0,
         start_child/3]).

-export([init/1]).

-define(CHILD(M), {M, {M, start_link, []}, permanent, 5000, worker, [M]}).

-spec start_link() -> {ok, pid()}.
start_link() ->
  supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-spec start_child(atom(), ex_fcgi:address(),
                  ex_fcgi:port_number()) -> {ok, pid()}.
start_child(Name, Address, Port) ->
  supervisor:start_child(?MODULE, [Name, Address, Port]).


-spec init([]) -> {ok, {{simple_one_for_one, 5, 10}, [?CHILD(ex_fcgi)]}}.
init([]) ->
  {ok, {{simple_one_for_one, 5, 10}, [?CHILD(ex_fcgi)]}}.
