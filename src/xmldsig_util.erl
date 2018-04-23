%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @doc Utility functions for modifying the XML
%%% @end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-module(xmldsig_util).
-author('alex@xalx.net').

%%_* Exports ===================================================================

-export([ add_namespace/2,
          c14n/1,
          key_value/1,
          to_bin/1,
          to_base64/1
        ]).

%%_* Includes ==================================================================

-include_lib("xmerl/include/xmerl.hrl").

%%_* API =======================================================================

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

to_bin(L) when is_list(L) ->
  list_to_binary(L);
to_bin(B) when is_binary(B) ->
  B.

to_base64(B) when is_binary(B) ->
  to_base64(binary_to_list(B));
to_base64(S) when is_list(S) ->
  base64:encode_to_string(S).

key_value(N) when is_integer(N) ->
  key_value(ssh_bits:mpint(N));
key_value(B) when is_binary(B) ->
  binary:part(B, {4, byte_size(B) - 4}).

%%%_* Emacs ====================================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
