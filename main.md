%%%
title = "OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP)"
abbrev = "OAuth DPoP"
ipr = "trust200902"
area = "Security"
workgroup = "Web Authorization Protocol"
keyword = ["security", "oauth2"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-ietf-oauth-dpop-02"
stream = "IETF"
status = "standard"
    
[[author]]
initials="D."
surname="Fett"
fullname="Daniel Fett"
organization="yes.com"
    [author.address]
    email = "mail@danielfett.de"

[[author]]
initials="B."
surname="Campbell"
fullname="Brian Campbell"
organization="Ping Identity"
    [author.address]
    email = "bcampbell@pingidentity.com"

[[author]]
initials="J."
surname="Bradley"
fullname="John Bradley"
organization="Yubico"
    [author.address]
    email = "ve7jtb@ve7jtb.com"


[[author]]
initials="T."
surname="Lodderstedt"
fullname="Torsten Lodderstedt"
organization="yes.com"
    [author.address]
    email = "torsten@lodderstedt.net"

[[author]]
initials="M."
surname="Jones"
fullname="Michael Jones"
organization="Microsoft"
    [author.address]
    email = "mbj@microsoft.com"
    uri = "https://self-issued.info/"
    
    
[[author]]
initials="D."
surname="Waite"
fullname="David Waite"
organization="Ping Identity"
    [author.address]
    email = "david@alkaline-solutions.com"

%%%

.# Abstract 

This document describes a mechanism for sender-constraining OAuth 2.0
tokens via a proof-of-possession mechanism on the application level.
This mechanism allows for the detection of replay attacks with access and refresh
tokens.

{mainmatter}


# Introduction {#Introduction}

DPoP, an abbreviation for Demonstrating Proof-of-Possession at the Application Layer,
is an application-level mechanism for
sender-constraining OAuth access and refresh tokens. It enables a client to
demonstrate proof-of-possession of a public/private key pair by including 
the `DPoP` header in an HTTP request. Using that header, an authorization
server is able to bind issued tokens to the public part of the client's 
key pair. Recipients of such tokens are then able to verify the binding of the
token to the key pair that the client has demonstrated that it holds via
the `DPoP` header, thereby providing some assurance that the client presenting
the token also possesses the private key.
In other words, the legitimate presenter of the token is constrained to be
the sender that holds and can prove possession of the private part of the
key pair.    

The mechanism described herein can be used in cases where other
methods of sender-constraining tokens that utilize elements of the underlying
secure transport layer, such as [@RFC8705] or [@I-D.ietf-oauth-token-binding],
are not available or desirable. For example, due to a sub-par user experience 
of TLS client authentication in user agents and a lack of support for HTTP token
binding, neither mechanism can be used if an OAuth client is a Single Page
Application (SPA) running in a web browser. Native applications installed
and run on a user's device, which often have dedicated protected storage
for cryptographic keys. are another example well positioned to benefit
from DPoP-bound tokens to guard against misuse of tokens by a compromised
or malicious resource.

DPoP can be used to sender-constrain access tokens regardless of the 
client authentication method employed. Furthermore, DPoP can
also be used to sender-constrain refresh tokens issued to public clients 
(those without authentication credentials associated with the `client_id`).

## Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED",
"MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [@RFC2119] [@RFC8174] when, and only when, they
appear in all capitals, as shown here.


This specification uses the terms "access token", "refresh token",
"authorization server", "resource server", "authorization endpoint",
"authorization request", "authorization response", "token endpoint",
"grant type", "access token request", "access token response", and
"client" defined by The OAuth 2.0 Authorization Framework [@!RFC6749].


# Main Objective {#Objective_Replay_Different_Endpoint}

Under the attacker model defined in [@I-D.ietf-oauth-security-topics],
the mechanism defined by this specification aims to prevent token
replay at a different endpoint.

More precisely, if an adversary is able to get hold of an access token
or refresh token because it set up a counterfeit authorization server
or resource server, the adversary is not able to replay the respective
token at another authorization or resource server.

Secondary objectives are discussed in (#Security).

# Concept

The main data structure introduced by this specification is a DPoP
proof JWT, described in detail below, sent as a header in an 
HTTP request. A client uses a DPoP proof JWT to prove
the possession of a private key corresponding to a certain public key.
Roughly speaking, a DPoP proof is a signature over a timestamp and some 
data of the HTTP request to which it is attached.

!---
~~~ ascii-art
+--------+                                          +---------------+
|        |--(A)-- Token Request ------------------->|               |
| Client |        (DPoP Proof)                      | Authorization |
|        |                                          |     Server    |
|        |<-(B)-- DPoP-bound Access Token ----------|               |
|        |        (token_type=DPoP)                 +---------------+
|        |
|        | 
|        |                                          +---------------+
|        |--(C)-- DPoP-bound Access Token --------->|               |
|        |        (DPoP Proof)                      |    Resource   |
|        |                                          |     Server    |
|        |<-(D)-- Protected Resource ---------------|               |
|        |                                          +---------------+
+--------+
~~~
!---
Figure: Basic DPoP Flow {#basic-flow}

The basic steps of an OAuth flow with DPoP are shown in (#basic-flow):

  * (A) In the Token Request, the client sends an authorization grant 
    (e.g., an authorization code, refresh token, etc.)  
    to the authorization server in order to obtain an access token
    (and potentially a refresh token). The client attaches a DPoP
    proof to the request in an HTTP header.
  * (B) The authorization server binds (sender-constrains) the access token to the
    public key claimed by the client in the DPoP proof; that is, the access token cannot
    be used without proving possession of the respective private key.
    If a refresh token is issued to a public client, it too is
    bound to the public key of the DPoP proof. 
  * (C) To use the access token the client has to prove
    possession of the private key by, again, adding a header to the
    request that carries the DPoP proof. The resource server needs to
    receive information about the public key to which the access token is bound. This
    information may be encoded directly into the access token (for
    JWT structured access tokens) or provided via token
    introspection endpoint (not shown). 
    The resource server verifies that the public key to which the
    access token is bound matches the public key of the DPoP proof.
  * (D) The resource server refuses to serve the request if the
    signature check fails or the data in the DPoP proof is wrong,
    e.g., the request URI does not match the URI claim in the DPoP
    proof JWT. The access token itself, of course, must also be 
    valid in all other respects. 
    
The DPoP mechanism presented herein is not a client authentication method.
In fact, a primary use case of DPoP is for public clients (e.g., single page
applications and native applications) that do not use client authentication. Nonetheless, DPoP
is designed such that it is compatible with `private_key_jwt` and all
other client authentication methods.

DPoP does not directly ensure message integrity but relies on the TLS
layer for that purpose. See (#Security) for details.

# DPoP Proof JWTs

DPoP introduces the concept of a DPoP proof, which is a JWT created by
the client and sent with an HTTP request using the `DPoP` header field.
A valid DPoP proof demonstrates to the server that the client holds the private
key that was used to sign the JWT. This enables authorization servers to bind
issued tokens to the corresponding public key (as described in (#access-token-request))
and for resource servers to verify the key-binding of tokens that
it receives (see (#http-auth-scheme)), which prevents said tokens from
being used by any entity that does not have access to the private key.

The DPoP proof demonstrates possession of a key and, by itself, is not
an authentication or access control mechanism. When presented
in conjunction with a key-bound access token as described in (#http-auth-scheme),
the DPoP proof provides additional assurance about the legitimacy of the client
to present the access token. But a valid DPoP proof JWT is not sufficient alone
to make access control decisions.


## DPoP Proof JWT Syntax {#DPoP-Proof}

A DPoP proof is a JWT ([@!RFC7519]) that is signed (using JWS,
[@!RFC7515]) using a private key chosen by the client (see below). The
header of a DPoP JWT contains at least the following parameters:

 * `typ`: type header, value `dpop+jwt` (REQUIRED).
 * `alg`: a digital signature algorithm identifier as per [@!RFC7518]
   (REQUIRED). MUST NOT be `none` or an identifier for a symmetric
   algorithm (MAC).
 * `jwk`: representing the public key chosen by the client, in JWK
   format, as defined in [@!RFC7515] (REQUIRED)
   
The body of a DPoP proof contains at least the following claims:

 * `jti`: Unique identifier for the DPoP proof JWT (REQUIRED).
   The value MUST be assigned such that there is a negligible 
   probability that the same value will be assigned to any 
   other DPoP proof used in the same context during the time window of validity.
   Such uniqueness can be accomplished by encoding (base64url or any other
   suitable encoding) at least 96 bits of
   pseudorandom data or by using a version 4 UUID string according to [@RFC4122].
   The `jti` SHOULD be used by the server for replay
   detection and prevention, see (#Token_Replay).
 * `htm`: The HTTP method for the request to which the JWT is
   attached, as defined in [@!RFC7231] (REQUIRED).
 * `htu`: The HTTP URI used for the request, without query and
   fragment parts (REQUIRED).
 * `iat`: Time at which the JWT was created (REQUIRED).


(#dpop-proof-jwt) shows an example DPoP proof JWT (with line breaks for display
purposes only) while (#dpop-proof) conceptually shows its content with 
JSON header and payload decoded and signature part omitted. 

!---
```
eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwi
eCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5
IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNy
diI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCI
sImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTY
yMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiO
SsX0x7NVY-FNyJK70nfbV37xRZT3Lg
```
!---
Figure: Example `DPoP` proof JWT {#dpop-proof-jwt}

!---
```
{
  "typ":"dpop+jwt",
  "alg":"ES256",
  "jwk": {
    "kty":"EC",
    "x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
    "y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
    "crv":"P-256"
  }
}.{
  "jti":"-BwC3ESc6acc2lTc",
  "htm":"POST",
  "htu":"https://server.example.com/token",
  "iat":1562262616
}
```
!---
Figure: Example JWT content of a `DPoP` proof header {#dpop-proof}

Of the HTTP content in the request, only the HTTP method and URI are
included in the DPoP JWT, and therefore only these 2 headers of the request
are covered by the DPoP proof and its signature.
The idea is sign just enough of the HTTP data to
provide reasonable proof-of-possession with respect to the HTTP request. But 
that it be a minimal subset of the HTTP data so as to avoid the substantial 
difficulties inherent in attempting to normalize HTTP messages. 
Nonetheless, DPoP proofs can be extended to contain other information of the
HTTP request (see also (#request_integrity)).

## Checking DPoP Proofs {#checking}

To check if a string that was received as part of an HTTP Request is a
valid DPoP proof, the receiving server MUST ensure that

 1. the string value is a well-formed JWT,
 1. all required claims are contained in the JWT,
 1. the `typ` field in the header has the value `dpop+jwt`,
 1. the algorithm in the header of the JWT indicates an asymmetric digital
    signature algorithm, is not `none`, is supported by the
    application, and is deemed secure,
 1. that the JWT is signed using the public key contained in the `jwk`
    header of the JWT,
 1. the `htm` claim matches the HTTP method value of the HTTP
    request in which the JWT was received (case-insensitive),
 1. the `htu` claims matches the HTTP URI value for the HTTP
    request in which the JWT was received, ignoring any query and
    fragment parts,
 1. the token was issued within an acceptable timeframe (see (#Token_Replay)), and
 1. that, within a reasonable consideration of accuracy and resource utilization,
    a JWT with the same `jti` value has not been received
    previously (see (#Token_Replay)).

Servers SHOULD employ Syntax-Based Normalization and Scheme-Based
Normalization in accordance with Section 6.2.2. and Section 6.2.3. of
[@!RFC3986] before comparing the `htu` claim.


# DPoP Access Token Request {#access-token-request}

To request an access token that is bound to a public key using DPoP, the client MUST 
provide a valid DPoP proof JWT in a `DPoP` header when making an access token
request to the authorization server's token endpoint. This is applicable for all
access token requests regardless of grant type (including, for example,
the common `authorization_code` and `refresh_token` grant types but also extension grants
such as the JWT authorization grant [@RFC7523]). The HTTPS request shown in
(#token-request-code) illustrates an such an access 
token request using an an authorization code grant with a DPoP proof JWT
in the `DPoP` header (extra line breaks and whitespace for display purposes only).

!---
~~~
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik
 VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR
 nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE
 QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIj
 oiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwia
 WF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg
 4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg
 
grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
&code_verifier=bEaL42izcC-o-xBk0K2vuJ6U-y1p9r_wW2dFWIWgjz-
~~~
!---
Figure: Token Request for a DPoP sender-constrained token using an authorization code {#token-request-code}

The `DPoP` HTTP header MUST contain a valid DPoP proof JWT.
If the DPoP proof is invalid, the authorization server issues an error 
response per Section 5.2 of [@RFC6749] with `invalid_dpop_proof` as the 
value of the `error` parameter. 

To sender-constrain the access token, after checking the validity of the
DPoP proof, the authorization server associates the issued access token with the
public key from the DPoP proof, which can be accomplished as described in (#Confirmation).
A `token_type` of `DPoP` in the access token
response signals to the client that the access token was bound to
its DPoP key and can used as described in (#http-auth-scheme). 
The example response shown in (#token-response) illustrates such a 
response. 

!---
~~~
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-cache, no-store

{
 "access_token": "Kz68mXK1EalYznwH-LCC7fBHAo4LjprzsPE_NeO6gxU",
 "token_type": "DPoP",
 "expires_in": 2677,
 "refresh_token": "QZkm29lexi8VnWg2zPW1x-tgGad0Ibc3s3EwM_Ni4-g"
}
~~~
!---
Figure: Access Token Response {#token-response}

The example response in (#token-response) included a refresh token, which the 
client can use to obtain a new access token when the the previous one expires.
Refreshing an access token is a token request using the `refresh_token`
grant type made to the the authorization server's token endpoint.  As with 
all access token requests, the client makes it a DPoP request by including 
a DPoP proof, which is shown in the (#token-request-rt) example
(extra line breaks and whitespace for display purposes only). 

!---
~~~
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik
 VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR
 nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE
 QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIj
 oiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwia
 WF0IjoxNTYyMjY1Mjk2fQ.pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5Qs
 GSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA

rant_type=refresh_token
&refresh_token=QZkm29lexi8VnWg2zPW1x-tgGad0Ibc3s3EwM_Ni4-g

~~~
!---
Figure: Token Request for a DPoP-bound token using a refresh token {#token-request-rt}

When an authorization server supporting DPoP issues a
refresh token to a public client that presents a valid DPoP proof at the
token endpoint, the refresh token MUST be bound
to the respective public key. The binding MUST be validated when the refresh
token is later presented to get new access tokens. As a result, such a client 
MUST present a DPoP proof for the same key that was used to obtain the refresh
token each time that refresh token is used to obtain a new access token. 
The implementation details of the binding of the refresh token are at the discretion of
the authorization server. The server both produces and
validates the refresh tokens that it issues so there's no interoperability
consideration in the specific details of the binding. 

An authorization server MAY elect to issue access tokens which are not DPoP bound,
which is signaled to the client with a value of `Bearer` in the `token_type` parameter 
of the access token response per [@RFC6750]. For a public client that is
also issued a refresh token, this has the effect of DPoP-binding the refresh token
alone, which can improve the security posture even when protected resources are not 
updated to support DPoP. 

Refresh tokens issued to confidential clients (those having
established authentication credentials with the authorization server) 
are not bound to the DPoP proof public key because they are already 
sender-constrained with a different existing mechanism. The OAuth 2.0 Authorization 
Framework [RFC6749] already requires that an authorization server bind 
refresh tokens to the client to which they were issued and that 
confidential clients authenticate to the authorization server when 
presenting a refresh token.  As a result, such refresh tokens
are sender-constrained by way of the client ID and the associated 
authentication requirement. This existing sender-constraining mechanism
is more flexible (e.g., it allows credential rotation for the client
without invalidating refresh tokens) than binding directly to a particular public key.

## Authorization Server Metadata {#as-meta}

This document introduces the following new authorization server metadata
[@RFC8414] parameter to signal the JWS `alg` values the authorization server
supports for DPoP proof JWTs:

`dpop_signing_alg_values_supported`
:   A JSON array containing a list of the JWS `alg` values supported
by the authorization server for DPoP proof JWTs. 


# Resource Access (Proof of Possession for Access Tokens) {#http-auth-scheme}

To make use of an access token that is bound to a public key
using DPoP, a client MUST prove the possession of the corresponding
private key by providing a DPoP proof in the `DPoP` request header.

A DPoP-bound access token is sent using the `Authorization` request
header field per Section 2 of [@!RFC7235] using an
authentication scheme of `DPoP`. The syntax of the `Authorization` 
header field for the `DPoP` scheme
uses the `token68` syntax defined in Section 2.1 of [@!RFC7235] 
(repeated below for ease of reference) for credentials. 
The Augmented Backus-Naur Form (ABNF) notation [@!RFC5234] syntax 
for DPoP Authorization scheme credentials is as follows:

!---
```
 token68    = 1*( ALPHA / DIGIT /
                   "-" / "." / "_" / "~" / "+" / "/" ) *"="

 credentials = "DPoP" 1*SP token68
```
!---
Figure: DPoP Authorization Scheme ABNF

For such an access token, a resource server
MUST check that a `DPoP` header was received in the HTTP request, 
check the header's contents according to the rules in (#checking), 
and check that the public key of the DPoP proof matches the public
key to which the access token is bound per (#Confirmation). 

The resource server MUST NOT grant access to the resource unless all
checks are successful.


!---
~~~
GET /protectedresource HTTP/1.1
Host: resource.example.org
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6IkJlQUxrYiJ9.eyJzdWI
 iOiJzb21lb25lQGV4YW1wbGUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbX
 BsZS5jb20iLCJhdWQiOiJodHRwczovL3Jlc291cmNlLmV4YW1wbGUub3JnIiwibmJmI
 joxNTYyMjYyNjExLCJleHAiOjE1NjIyNjYyMTYsImNuZiI6eyJqa3QiOiIwWmNPQ09S
 Wk5ZeS1EV3BxcTMwalp5SkdIVE4wZDJIZ2xCVjN1aWd1QTRJIn19.vsFiVqHCyIkBYu
 50c69bmPJsj8qYlsXfuC6nZcLl8YYRNOhqMuRXu6oSZHe2dGZY0ODNaGg1cg-kVigzY
 hF1MQ
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik
 VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR
 nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE
 QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIj
 oiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0Z
 WRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOH0.lNhmpAX1WwmpBvwhok4E74kWCiGB
 NdavjLAeevGy32H3dbF0Jbri69Nm2ukkwb-uyUI4AUg1JSskfWIyo4UCbQ
~~~
!---
Figure: Protected Resource Request with a DPoP sender-constrained access token {#protected-resource-request}

Upon receipt of a request for a URI of a protected resource within 
the protection space requiring DPoP authorization, if the request does
not include valid credentials or does not contain an access 
token sufficient for access to the protected resource, the server
can reply with a challenge using the 401 (Unauthorized) status code
([@!RFC7235], Section 3.1) and the `WWW-Authenticate` header field
([@!RFC7235], Section 4.1). The server MAY include the 
`WWW-Authenticate` header in response to other conditions as well.

In such challenges:

*  The scheme name is `DPoP`.
*  The authentication parameter `realm` MAY be included to indicate the 
scope of protection in the manner described in [@!RFC7235], Section 2.2.
*  A `scope` authentication parameter MAY be included as defined in 
[@!RFC6750], Section 3.
*  An `error` parameter ([@!RFC6750], Section 3) SHOULD be included
to indicate the reason why the request was declined,
if the request included an access token but failed authorization. 
Parameter values are described in Section 3.1 of [@!RFC6750]. 
* An `error_description` parameter ([@!RFC6750], Section 3) MAY be included 
along with the `error` parameter to provide developers a human-readable
explanation that is not meant to be displayed to end-users.
* An `algs` parameter SHOULD be included to signal to the client the 
JWS algorithms that are acceptable for the DPoP proof JWT. 
The value of the parameter is a space-delimited list of JWS `alg` (Algorithm)
 header values ([@!RFC7515], Section 4.1.1).
* Additional authentication parameters MAY be used and unknown parameters 
MUST be ignored by recipients


For example, in response to a protected resource request without
authentication:
!---
```
 HTTP/1.1 401 Unauthorized
 WWW-Authenticate: DPoP realm="WallyWorld", algs="ES256 PS256"
```
!---

And in response to a protected resource request that was rejected 
because the confirmation of the DPoP binding in the access token failed: 

!---
```
 HTTP/1.1 401 Unauthorized
 WWW-Authenticate: DPoP realm="WallyWorld", error="invalid_token",
   error_description="Invalid DPoP key binding", algs="ES256"
```
!---

# Public Key Confirmation {#Confirmation}

It MUST be ensured that resource servers can reliably identify whether
a token is bound using DPoP and learn the public key to which the
token is bound.

Access tokens that are represented as JSON Web Tokens (JWT) [@!RFC7519]
MUST contain information about the DPoP public key (in JWK format) in
the member `jkt` of the `cnf` claim, as shown in (#cnf-claim).

The value in `jkt` MUST be the base64url encoding [@!RFC7515] of
the JWK SHA-256 Thumbprint (according to [@!RFC7638]) of the public
key to which the access token is bound.

!---
```
{
  "sub":"someone@example.com",
  "iss":"https://server.example.com",
  "aud":"https://resource.example.org",
  "nbf":1562262611,
  "exp":1562266216,
  "cnf":{
      "jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
  }
}
```
!---
Figure: Example access token body with `cnf` claim {#cnf-claim}

When access token introspection is used, the same `cnf` claim as above
MUST be contained in the introspection response.

Resource servers MUST ensure that the fingerprint of the public key in
the DPoP proof JWT equals the value in the `jkt` claim in the access
token or introspection response.


# Security Considerations {#Security}

In DPoP, the prevention of token replay at a different endpoint (see
(#Objective_Replay_Different_Endpoint)) is achieved through the
binding of the DPoP proof to a certain URI and HTTP method. DPoP does
not, however, achieve the same level of protection as TLS-based
methods such as OAuth Mutual TLS [@RFC8705] or OAuth Token
Binding [@I-D.ietf-oauth-token-binding] (see also (#Token_Replay) and (#request_integrity)). 
TLS-based mechanisms can leverage a tight integration
between the TLS layer and the application layer to achieve a very high
level of message integrity and replay protection. Therefore, it is
RECOMMENDED to prefer TLS-based methods over DPoP if such methods are
suitable for the scenario at hand.


## DPoP Proof Replay {#Token_Replay}

If an adversary is able to get hold of a DPoP proof JWT, the adversary
could replay that token at the same endpoint (the HTTP endpoint
and method are enforced via the respective claims in the JWTs). To
prevent this, servers MUST only accept DPoP proofs for a limited time
window after their `iat` time, preferably only for a relatively brief period.
Servers SHOULD store the `jti` value of each DPoP proof for the time window in
which the respective DPoP proof JWT would be accepted and decline HTTP requests
for which the `jti` value has been seen before. In order to guard against 
memory exhaustion attacks a server SHOULD reject DPoP proof JWTs with unnecessarily
large `jti` values or store only a hash thereof.    

Note: To accommodate for clock offsets, the server MAY accept DPoP
proofs that carry an `iat` time in the near future (e.g., a few
seconds in the future).

## Signed JWT Swapping

Servers accepting signed DPoP proof JWTs MUST check the `typ` field in the
headers of the JWTs to ensure that adversaries cannot use JWTs created
for other purposes.

## Signature Algorithms

Implementers MUST ensure that only asymmetric digital signature algorithms that
are deemed secure can be used for signing DPoP proofs. In particular,
the algorithm `none` MUST NOT be allowed.

## Message Integrity {#request_integrity}

DPoP does not ensure the integrity of the payload or headers of
requests. The DPoP proofs only contains claims for the HTTP URI and
method, but not, for example, the message body or general request
headers.

This is an intentional design decision intended to keep DPoP simple to use, but
as described, makes DPoP potentially susceptible to replay attacks
where an attacker is able to modify message contents and headers. In
many setups, the message integrity and confidentiality provided by TLS
is sufficient to provide a good level of protection.

Implementers that have stronger requirements on the integrity of
messages are encouraged to either use TLS-based mechanisms or signed
requests. TLS-based mechanisms are in particular OAuth Mutual TLS
[@RFC8705] and OAuth Token Binding
[@I-D.ietf-oauth-token-binding].

Note: While signatures covering other parts of requests are out of the scope of
this specification, addional information to be signed can be
added into DPoP proofs.





# IANA Considerations {#IANA}
      
##  OAuth Access Token Type Registration

This specification requests registration of the following access token
type in the "OAuth Access Token Types" registry [@IANA.OAuth.Params]
established by [@!RFC6749].

 * Type name: `DPoP`
 * Additional Token Endpoint Response Parameters: (none)
 * HTTP Authentication Scheme(s): `DPoP`
 * Change controller: IESG
 * Specification document(s): [[ this specification ]]

## HTTP Authentication Scheme Registration

This specification requests registration of the following scheme in the 
"Hypertext Transfer Protocol (HTTP) Authentication Scheme Registry" [@RFC7235;@IANA.HTTP.AuthSchemes]:

 * Authentication Scheme Name: `DPoP`
 * Reference: [[ (#http-auth-scheme) of this specification ]]

## Media Type Registration
    
[[
Is a media type registration at [@IANA.MediaTypes] necessary for `application/dpop+jwt`? 
There is a `+jwt` structured syntax suffix registered already at [@IANA.MediaType.StructuredSuffix]
by Section 7.2 of [@RFC8417], which is maybe sufficient? A full-blown registration
of `application/dpop+jwt` seems like it'd be overkill. 
The `dpop+jwt` is used in the JWS/JWT `typ` header for explicit typing of the JWT per 
Section 3.11 of [@RFC8725] but it is not used anywhere else (such as the `Content-Type` of HTTP messages). 

Note that there does seem to be some precedence for [@IANA.MediaTypes] registration with 
 [@I-D.ietf-oauth-access-token-jwt], [@I-D.ietf-oauth-jwsreq], [@RFC8417], and of course [@RFC7519].
But precedence isn't always right. 
]]

## JWT Confirmation Methods Registration

This specification requests registration of the following value
in the IANA "JWT Confirmation Methods" registry [@IANA.JWT]
for JWT `cnf` member values established by [@!RFC7800].
          
 * Confirmation Method Value:  `jkt`
 * Confirmation Method Description: JWK SHA-256 Thumbprint
 * Change Controller:  IESG
 * Specification Document(s):  [[ (#Confirmation) of this specification ]]

## JSON Web Token Claims Registration

This specification requests registration of the following Claims in the 
IANA "JSON Web Token Claims" registry [@IANA.JWT] established by [@RFC7519].

HTTP method:

 *  Claim Name: `htm`
 *  Claim Description: The HTTP method of the request 
 *  Change Controller: IESG
 *  Specification Document(s):  [[ (#DPoP-Proof) of this specification ]]
 
HTTP URI:
 
 *  Claim Name: `htu`
 *  Claim Description: The HTTP URI of the request (without query and fragment parts)
 *  Change Controller: IESG
 *  Specification Document(s):  [[ (#DPoP-Proof) of this specification ]]
 
## HTTP Message Header Field Names Registration
 
This document specifies the following new HTTP header fields,
registration of which is requested in the "Permanent Message Header
Field Names" registry [@IANA.Headers] defined in [@RFC3864].
 
 *  Header Field Name: `DPoP`
 *  Applicable protocol: HTTP
 *  Status: standard
 *  Author/change Controller: IETF
 *  Specification Document(s): [[ this specification ]]

## Authorization Server Metadata Registration
   
This specification requests registration of the following values
in the IANA "OAuth Authorization Server Metadata" registry [IANA.OAuth.Parameters]
established by [@RFC8414].

 *  Metadata Name:  `dpop_signing_alg_values_supported`
 *  Metadata Description:  JSON array containing a list of the JWS algorithms supported for DPoP proof JWTs
 *  Change Controller:  IESG
 *  Specification Document(s):  [[ (#as-meta) of this specification ]]

{backmatter}

# Acknowledgements {#Acknowledgements}
      
We would like to thank 
Annabelle Backman,
Dominick Baier,
William Denniss,
Vladimir Dzhuvinov,
Mike Engan,
Nikos Fotiou,
Mark Haine,
Dick Hardt,
Bjorn Hjelm,
Jared Jennings,
Steinar Noem,
Neil Madden,
Rob Otto,
Aaron Parecki,
Michael Peck,
Paul Querna,
Justin Richer,
Filip Skokan,
Dave Tonge,
Jim Willeke,
and others (please let us know, if you've been mistakenly omitted)
for their valuable input, feedback and general support of this work.

This document resulted from discussions at the 4th OAuth Security
Workshop in Stuttgart, Germany. We thank the organizers of this
workshop (Ralf Kusters, Guido Schmitz).

# Document History

   [[ To be removed from the final specification ]]
 
  -02
  
   * Editorial updates
   
  -01
  
   * Editorial updates
   * Attempt to more formally define the DPoP Authorization header scheme
   * Define the 401/WWW-Authenticate challenge 
   * Added `invalid_dpop_proof` error code for DPoP errors in token request 
   * Fixed up and added to the IANA section
   * Added `dpop_signing_alg_values_supported` authorization server metadata
   * Moved the Acknowledgements into an Appendix and added a bunch of names (best effort)
   
   -00 [[ Working Group Draft ]]

   * Working group draft

   -04

   * Update OAuth MTLS reference to RFC 8705
   * Use the newish RFC v3 XML and HTML format

   -03 
   
   * rework the text around uniqueness requirements on the jti claim in the DPoP proof JWT
   * make tokens a bit smaller by using `htm`, `htu`, and `jkt` rather than `http_method`, `http_uri`, and `jkt#S256` respectively
   * more explicit recommendation to use mTLS if that is available
   * added David Waite as co-author
   * editorial updates 

   -02
   
   * added normalization rules for URIs
   * removed distinction between proof and binding
   * "jwk" header again used instead of "cnf" claim in DPoP proof
   * renamed "Bearer-DPoP" token type to "DPoP"
   * removed ability for key rotation
   * added security considerations on request integrity
   * explicit advice on extending DPoP proofs to sign other parts of the HTTP messages
   * only use the jkt#S256 in ATs
   * iat instead of exp in DPoP proof JWTs
   * updated guidance on token_type evaluation


   -01
   
   * fixed inconsistencies
   * moved binding and proof messages to headers instead of parameters
   * extracted and unified definition of DPoP JWTs
   * improved description


   -00 

   *  first draft
   

<reference anchor="IANA.OAuth.Params" target="https://www.iana.org/assignments/oauth-parameters">
 <front>
   <title>OAuth Parameters</title>
   <author><organization>IANA</organization></author>
 </front>
</reference>

<reference anchor="IANA.MediaType.StructuredSuffix" target="https://www.iana.org/assignments/media-type-structured-suffix">
 <front>
   <title>Structured Syntax Suffix Registry</title>
   <author><organization>IANA</organization></author>
 </front>
</reference>

<reference anchor="IANA.MediaTypes" target="https://www.iana.org/assignments/media-types">
 <front>
   <title>Media Types</title>
   <author><organization>IANA</organization></author>
 </front>
</reference>

<reference anchor="IANA.HTTP.AuthSchemes" target="https://www.iana.org/assignments/http-authschemes">
 <front>
   <title>Hypertext Transfer Protocol (HTTP) Authentication Scheme Registry</title>
   <author><organization>IANA</organization></author>
 </front>
</reference>

<reference anchor="IANA.JWT" target="http://www.iana.org/assignments/jwt">
<front>
  <title>JSON Web Token Claims</title>
  <author><organization>IANA</organization></author>
  <date/>
</front>
</reference>

<reference anchor="IANA.Headers" target="https://www.iana.org/assignments/message-headers">
<front>
  <title>Message Headers</title>
  <author><organization>IANA</organization></author>
  <date/>
</front>
</reference>


