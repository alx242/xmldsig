%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% doc@ This is the start of a xmldsig implementation for Erlang
%%%      see http://www.w3.org/TR/xmldsig-core/
%%%      and http://www.di-mgt.com.au/xmldsig.html
%%%
%%% "THE BEER-WARE LICENSE" (Revision 42): <alex@xalx.net> wrote this
%%% file. As long as you retain this notice you can do whatever you
%%% want with this stuff. If we meet some day, and you think this
%%% stuff is worth it, you can buy me a beer in return Alexander
%%% Schüssler
%%%
%%% @end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
-module(xmldsig).
-author('alex@xalx.net').

%%_* Exports ===================================================================

-export([create_signature/4,
         read_private_rsa_pem_file/1,
         read_cert_pem_file/1,
         verify_sign/1,
         verify_sign/2]).

%%_* Includes ==================================================================

-include_lib("public_key/include/public_key.hrl").
-include_lib("xmerl/include/xmerl.hrl").

-define(SIGN_ALG, sha).    % sha
-define(NS_ALG,   "sha1"). % sha1

%%_* API =======================================================================

-spec verify_sign(string()) -> ok | no_return().

%% @doc Check a signed xml using the certificate present in the
%%      <Security> element verify that the signing of the xml is ok.
%%
%% NOTE: This only works if one certificate is present in the xml
%%       since with multiple once it isn't possible to determine which
%%       one to verify against.
%%
%% NOTE: Currently the way signature is removed from the xml structure
%%       is to brutal and needs to be support more variations of how
%%       the signature can be stored using xmldsig. This is a major
%%       FIXME atm!
verify_sign(Xml) ->
  {XmlElement, _}       = xmerl_scan:string(Xml),
  {_, string, X509Cert} =
    xmerl_xpath:string("string(//X509Certificate[text()])", XmlElement),
  verify_sign(Xml, X509Cert).

-spec verify_sign(string() | #xmlElement{}, string()) -> ok | no_return().

%% @doc Verify a signature against a specified certificate.
verify_sign(Xml, B64X509) when is_list(Xml) ->
  {XmlElement, []}    = xmerl_scan:string(Xml),
  X509                = base64:decode(B64X509),
  NoSignatureXml      = lists:flatten(
                          xmerl:export_element(XmlElement,
                                               xmldsig_remove_signature)),
  {_, string, Digest} = xmerl_xpath:string("string(//DigestValue[text()])",
                                           XmlElement),
  SignatureXml        = lists:flatten(
                          xmerl:export_content(
                            xmerl_xpath:string("//SignedInfo", XmlElement),
                            xmerl_xml)),
  do_verify(XmlElement, NoSignatureXml, Digest, SignatureXml, X509).

-spec create_signature(list(), list(), tuple(), tuple()) ->
                          list().

%% @doc Will create signature according to the specs of xmldsig. The
%%      signature can then be pushed into any xml structure. Currently
%%      being work in progess is a support function to insert a xml
%%      into a specified position in the xml.
create_signature(Xml, RSAPassword,
                 {'RSAPrivateKey', _RSAder, _} = RSAEnc,
                 {'Certificate', X509der, _}) ->
  #'RSAPrivateKey'{modulus=Modulus,              % N
                   publicExponent=PubExp,        % E
                   privateExponent=PrivateExp} = % D
   public_key:pem_entry_decode(RSAEnc, [RSAPassword]),

  RsaPrivateKey = [ xmldsig_util:key_value(PubExp),
                    xmldsig_util:key_value(Modulus),
                    xmldsig_util:key_value(PrivateExp)
                  ],

  SignedInfo    = signed_info(Xml),
  SignatureElem = signature(SignedInfo, RsaPrivateKey, X509der),
  to_xml([SignatureElem]).

-spec read_private_rsa_pem_file(list()) ->
                                   tuple().

%% @doc Will try and read a private rsa key from a pem file
read_private_rsa_pem_file(PemFile) ->
  read_pem(PemFile, 'RSAPrivateKey').

-spec read_cert_pem_file(list()) ->
                            tuple().

%% @doc Will try and read a X509 certificate from a pem file
read_cert_pem_file(PemFile) ->
  read_pem(PemFile, 'Certificate').

%%_* Internal ==================================================================

%% @doc Kindly extract the wanted pem data from a pem file. Will
%%      ignore any unwated data structure in case multiple have been
%%      stored in the same file.
read_pem(PemFile, Match) ->
  {ok, Bin}   = file:read_file(PemFile),
  AllData     = public_key:pem_decode(Bin),

  MatchFun    = fun({Match1, _, _}) when Match1 =:= Match -> true;
                   (_Whatever) -> false
                end,
  case lists:filter(MatchFun, AllData) of
    [] ->
      hd(AllData);
    [Encoded | _] ->
      Encoded
  end.

%% @doc Creates a simple xmerl xml structure of the <Signature> xml
%%      structure according to xmldsig spec.
signature(SignedInfo, RsaPrivateKey = [PubExp, Modulus, _], X509) ->
  SignedInfoXml  = xmerl:export_simple_content([SignedInfo], xmerl_xml),

  C14NSignedInfo = xmldsig_util:c14n(SignedInfoXml),
  SignatureValue = rm_unwanted(rsa_sha(C14NSignedInfo, RsaPrivateKey)),

  ModulusB64     = rm_unwanted(xmldsig_util:to_base64(Modulus)),
  ExponentB64    = rm_unwanted(xmldsig_util:to_base64(PubExp)),
  X509B64        = rm_unwanted(xmldsig_util:to_base64(X509)),

  {'Signature', [{xmlns, "http://www.w3.org/2000/09/xmldsig#"}],
   [SignedInfo,
    {'SignatureValue', [], [SignatureValue]},
    {'KeyInfo', [],
     [{'X509Data', [], [{'X509Certificate', [], [X509B64]}]},
      {'KeyValue', [], [{'RSAKeyValue', [], [{'Modulus', [], [ModulusB64]},
                                             {'Exponent', [], [ExponentB64]}]}
                       ]}
     ]}
   ]}.

signed_info(Xml) ->
  Digest = rm_unwanted(digest(xmldsig_util:c14n(Xml), ?SIGN_ALG)),

  {'SignedInfo', [{xmlns, "http://www.w3.org/2000/09/xmldsig#"}],
   [{'CanonicalizationMethod',
     [{'Algorithm', "http://www.w3.org/2001/10/xml-exc-c14n#"}], []},
    {'SignatureMethod',
     [{'Algorithm', "http://www.w3.org/2000/09/xmldsig#rsa-" ++ ?NS_ALG}], []},
    {'Reference', [{'URI', ""}],
     [{'Transforms', [],
       [{'Transform',
         [{'Algorithm',
           "http://www.w3.org/2000/09/xmldsig#enveloped-signature"}], []},
        {'Transform',
         [{'Algorithm',
           "http://www.w3.org/2001/10/xml-exc-c14n#"}], []}
       ]
      },
      {'DigestMethod', [{'Algorithm',
                         "http://www.w3.org/2000/09/xmldsig#" ++ ?NS_ALG}], []},
      {'DigestValue', [], [Digest]}
     ]}
   ]}.

%% @doc Sign a data string using the private rsa key.
%%      Key = [E,N,D]  E=PublicExponent N=PublicModulus  D=PrivateExponent
rsa_sha(Data, RsaPrivateKey) ->
  Payload = xmldsig_util:to_bin(lists:flatten(Data)),
  xmldsig_util:to_base64(crypto:sign(rsa, ?SIGN_ALG, Payload, RsaPrivateKey)).

%% @doc Do a two step verification of both the digest and the rsa
%% signature.
do_verify(XmlElement, NoSignatureXml, Digest, SignatureXml, X509) ->
  case verify_digest(NoSignatureXml, Digest) of
    false -> throw(bad_digest);
    true  -> ok
  end,
  case verify_rsa(XmlElement, SignatureXml, X509) of
    false -> throw(bad_signature);
    true  -> ok
  end.

%% @doc Check that the canonical form of the xml (without the
%%      signature gets the same digest as what was found inside the
%%      signature element.
verify_digest(NoSignatureXml, Digest) ->
  CanonicalDigest = digest(xmldsig_util:c14n(NoSignatureXml), ?SIGN_ALG),
  rm_unwanted(CanonicalDigest) =:= rm_unwanted(Digest).

%% @doc Create a digest of chunk of data
digest(Data, ?SIGN_ALG) -> xmldsig_util:to_base64(crypto:hash(?SIGN_ALG, Data));
digest(_,    _)   -> throw(unsupported_crypto_algorithm).

%% @doc Pulls out signature digest value and verifies that it is
%%      correctly signed using the original data and the public key
verify_rsa(XmlElement, SignatureXmlNoNs, X509) ->
  RsaPubKey        = get_public_key_rsa(X509),
  {_, string,
   SignatureValue} =
    xmerl_xpath:string("string(//SignatureValue[string()])", XmlElement),
  SignatureXml     =
    xmldsig_util:add_namespace(SignatureXmlNoNs,
                               "http://www.w3.org/2000/09/xmldsig#"),
  % NOTE: This converts string to binary
  SignatureXmlBin  = xmldsig_util:to_bin(xmldsig_util:c14n(SignatureXml)),
  SignatureValBin  = xmldsig_util:to_bin(base64:decode(SignatureValue)),
  crypto:verify(rsa, sha, SignatureXmlBin, SignatureValBin, RsaPubKey).

-spec get_public_key_rsa(binary()) -> list(binary()).
%% @doc Extract the public_key from a X509 certificate
%%      Key = [E,N]  E=PublicExponent N=PublicModulusKey
get_public_key_rsa(X509) ->
  #'OTPCertificate'{tbsCertificate=TBS} =
    public_key:pkix_decode_cert(X509, otp),
  PublicKey                             =
    TBS#'OTPTBSCertificate'.subjectPublicKeyInfo,
  #'RSAPublicKey'{modulus=N,
                  publicExponent=E}     =
    PublicKey#'OTPSubjectPublicKeyInfo'.subjectPublicKey,
  [xmldsig_util:key_value(E), xmldsig_util:key_value(N)].

%% @doc Remove whitespace characters, newlines, tabs...
rm_unwanted(String) ->
  re:replace(String, "\\s+", "", [global, {return, list}]).

to_xml(Elem) ->
  lists:flatten(
    xmerl:export_simple(Elem, xmerl_xml, [{prolog, []}])
  ).

%%%_* Emacs ====================================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
