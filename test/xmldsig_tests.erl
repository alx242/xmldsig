%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% doc@ Simple test cases
%%%
%%% @end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-module(xmldsig_tests).
-author('alex@xalx.net').

%%_* Includes ==================================================================
-include_lib("eunit/include/eunit.hrl").

%%_* Tests =====================================================================
sign_and_verify_test() ->
  Signature =  get_a_signature(
                 "<xml>apapapapa<security></security>asdasd</xml>"),
  NewXml    = "<xml>apapapapa<security>"++Signature++"</security>asdasd</xml>",
  ?assertEqual(ok, xmldsig:verify_sign(NewXml)).

sign_and_verify_bad_test() ->
  Signature =  get_a_signature(
                 "<xml>apapapapa<security></security>asdasd</xml>"),
  BadXml    = "<xml>APA<security>"++Signature++"</security>APA</xml>",
  ?assertEqual(bad_digest, catch xmldsig:verify_sign(BadXml)).

%%_* Internal ==================================================================
get_a_signature(Xml) ->
  Rsa  = xmldsig:read_private_rsa_pem_file(
           filename:join(code:priv_dir(xmldsig), "mykey.pem")),
  X509 = xmldsig:read_cert_pem_file(
           filename:join(code:priv_dir(xmldsig), "cert.pem")),
  xmldsig:create_signature(Xml, [], Rsa, X509).

%%%_* Emacs ====================================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
