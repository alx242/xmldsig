%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @doc Utility functions for modifying the XML
%%% @end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-module(xmldsig_util).
-author('alex@xalx.net').

%%_* Exports ===================================================================

-export([mpint/1, add_namespace/2, c14n/1]).

%%_* Includes ==================================================================

-include_lib("xmerl/include/xmerl.hrl").

%%_* API =======================================================================

-spec mpint(string() | binary()) -> binary().

%% @doc Convert a string (raw xml data) and convert it to a
%%      multi-precision integer. The first part of the binary (32
%%      bits) reveals the size of the binary.
mpint(String) when is_list(String)    ->
  mpint(list_to_binary(String));
mpint(Binary) when is_binary(Binary) ->
  <<(size(Binary)):32/integer, Binary/binary>>.

-spec add_namespace(string() | #xmlElement{}, string()) -> string().

%% @doc Check if a xml alread has a name space otherwise add it
add_namespace(Xml, Namespace) when is_list(Xml)                      ->
  {XmlElement, _} = xmerl_scan:string(Xml),
  add_namespace(XmlElement, Namespace);
add_namespace(#xmlElement{attributes=Attrs} = XmlElement, Namespace) ->
  NotThere = lists:filter(fun(#xmlAttribute{name=Name, value=Value}) ->
                              Name=:=xmlns andalso Value=:=Namespace
                          end, Attrs),
  NewXmlElement =
    case NotThere =:= [] of
      true  -> Pos = length(Attrs) + 1,
               NewAttrs = Attrs ++ [#xmlAttribute{name=xmlns,
                                                  value=Namespace,
                                                  pos=Pos}],
               XmlElement#xmlElement{attributes=NewAttrs};
      false -> XmlElement
    end,
  xmerl:export_content([NewXmlElement], xmerl_xml).

-spec c14n(string()) -> string().

%% @doc Try and canonicalize the XML. Uses the xmldsig_c14n callback
%%      module during a xmerl export.
c14n(Xml) ->
  {Element, _} = xmerl_scan:string(lists:flatten(Xml)),
  xmerl_ucs:to_utf8(lists:flatten(xmerl:export([Element], xmldsig_c14n))).

%%%_* Emacs ====================================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
