%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% @doc Callback xml export to remove signature from xml
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-module(xmldsig_remove_signature).
-author('alex@xalx.net').

%%_* Exports ===================================================================

-export(['#xml-inheritance#'/0,
         '#root#'/4,
         '#element#'/5,
         '#text#'/1]).

-include_lib("xmerl/include/xmerl.hrl").

%%_* Callbacks ==================================================================

'#xml-inheritance#'() -> xmerl_xml:'#xml-inheritance#'().

'#text#'(Text) -> xmerl_xml:'#text#'(Text).

%% @doc Makes sure the signature node is dropped. FIXME: This will
%%      drop all signature nodes no matter where they are in the
%%      xml. This to brutal with the signature at root level or
%%      similar. FIXME FIXME FIXME
'#element#'(Tag, Data, Attrs, Parents, Element) ->
  case is_in(Element#xmlElement.content) of
    true  -> xmerl_xml:'#element#'(Tag, [], Attrs, Parents, Element);
    false -> xmerl_xml:'#element#'(Tag, Data, Attrs, Parents, Element)
  end.

'#root#'(Data, Attrs, X3, Element) ->
  xmerl_xml:'#root#'(Data, Attrs, X3, Element).

%%_* Internal ==================================================================

is_in([])                              -> false;
is_in([#xmlElement{name=Name} | Rest]) ->
  case string:to_lower(atom_to_list(Name)) =:= "signature" of
    true  -> true;
    false -> is_in(Rest)
  end;
is_in([_ | Rest])                      -> is_in(Rest).

%%%_* Emacs ====================================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
