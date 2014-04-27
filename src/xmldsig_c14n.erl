%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% @doc Canonicalization/c14n of xml. Please see here for more info:
%%      http://www.w3.org/TR/2001/REC-xml-c14n-20010315
%%
%%      Will try and do these parts
%%      - expands tags
%%      - removes newlines surrouding root elements
%%      - removes all comments
%%      - removes any extra whitespaces within elements
%%
%%      NOTE: The whole canocicalization process is probably not
%%      finished since the spec is much more expensive than these
%%      parts and should thus be expanded.
%%
%%      NORE: It should be possible to do canonicalization with
%%      comments if it is wanted but this isn't supported as of yet.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-module(xmldsig_c14n).
-author('alex@xalx.net').

%%_* Exports ===================================================================

-export(['#xml-inheritance#'/0,
         '#root#'/4,
         '#element#'/5,
         '#text#'/1]).

-include_lib("xmerl/include/xmerl.hrl").

%%_* Tag Callbacks =============================================================

'#xml-inheritance#'() -> [].

'#text#'(Text) -> xmerl_lib:export_text(Text).

'#element#'(Tag, Data, Attrs, _Parents, _Element)  ->
  expand_tags(Tag, Data, Attrs).

%% @doc If a prolog attribute has been pushed into the xml this is append
%%      to the front of the root element.
%%
%%      NOTE: Enables the <?xml version="1.0" ...> - tag
%%
%%      Also removes all newlines surrounding the root element.
'#root#'(Data, [#xmlAttribute{name=prolog, value=V}], [], _Element) ->
  [V, Data];
'#root#'(Data, _Attrs, [], _Element)                                ->
  [string:strip(Data, both, 10)].

%%_* Internal ==================================================================

%% Expands tags that perhaps are shortend. e.g:
%% <small_tag/> -> <small_tag></small_tag>
expand_tags(Tag, Data, Attrs) ->
  [xmerl_lib:start_tag(Tag, Attrs), Data, xmerl_lib:end_tag(Tag)].

%%%_* Emacs ====================================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
