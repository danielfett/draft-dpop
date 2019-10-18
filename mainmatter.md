
{{introduction.md}}

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
proof JWT, described in detail below. A client uses a DPoP proof JWT to prove
the possession of a private key belonging to a certain public key.
Roughly speaking, a DPoP proof is a signature over some data of the
request to which it is attached to and a timestamp.

!---
~~~ ascii-art
+--------+                                          +---------------+
|        |--(A)-- Token Request ------------------->|               |
| Client |        (DPoP Proof)                      | Authorization |
|        |                                          |     Server    |
|        |<-(B)-- DPoP-bound Access Token ----------|               |
|        |        (token_type=DPoP)                 +---------------+
|        |        PoP Refresh Token for public clients
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
Figure 1: Basic DPoP Flow

The basic steps of an OAuth flow with DPoP are shown in Figure 1:

  * (A) In the Token Request, the client sends an authorization code
    to the authorization server in order to obtain an access token
    (and potentially a refresh token). The client attaches a DPoP
    proof to the request in an HTTP header.
  * (B) The AS binds (sender-constrains) the access token to the
    public key claimed by the client in the DPoP proof; that is, the access token cannot
    be used without proving possession of the respective private key.
    This is signaled to the client by using the `token_type` value
    `DPoP`. 
  * If a refresh token is issued to a public client, it is
    sender-constrained in the same way. For confidential clients,
    refresh tokens are bound to the `client_id`, which is more
    flexible than binding it to a particular public key.
  * (C) If the client wants to use the access token, it has to prove
    possession of the private key by, again, adding a header to the
    request that contains a DPoP proof. The resource server needs to
    receive information about which public key to check against. This
    information is either encoded directly into the access token (for
    JWT structured access tokens), or provided at the token
    introspection endpoint of the authorization server (not
    shown).
  * (D) The resource server refuses to serve the request if the
    signature check fails or the data in the DPoP proof is wrong,
    e.g., the request URI does not match the URI claim in the DPoP
    proof JWT.
  * When a refresh token that is sender-constrained using DPoP is used
    by the client, the client has to provide a DPoP proof just as in
    the case of a resource access. The new access token will be bound
    to the same public key.

The mechanism presented herein is not a client authentication method.
In fact, a primary use case is public clients (single page
applications) that do not use client authentication. Nonetheless, DPoP
is designed such that it is compatible with `private_key_jwt` and all
other client authentication methods.

DPoP does not directly ensure message integrity but relies on the TLS
layer for that purpose. See (#Security) for details.

# DPoP Proof JWTs

DPoP uses so-called DPoP proof JWTs for binding public keys and proving
knowledge about private keys.

## Syntax

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
   detection and prevention. See (#Security) in the Security Considerations.
 * `htm`: The HTTP method for the request to which the JWT is
   attached, as defined in [@!RFC7231] (REQUIRED).
 * `htu`: The HTTP URI used for the request, without query and
   fragment parts (REQUIRED).
 * `iat`: Time at which the JWT was created (REQUIRED).


An example DPoP proof is shown in Figure 2.

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
Figure 2: Example JWT content for `DPoP` proof header.

Note: To keep DPoP simple to implement, only the HTTP method and URI
are signed in DPoP proofs. Nonetheless, DPoP proofs can be extended to
contain other information of the HTTP request (see also
(#request_integrity)).

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


# Token Request (Binding Tokens to a Public Key)

To bind a token to a public key in the token request, the client MUST
provide a valid DPoP proof JWT in a `DPoP` header. The HTTPS request shown
in Figure 3 illustrates the protocol for this (with extra line breaks
for display purposes only).


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
Figure 3: Token Request for a DPoP sender-constrained token.

The HTTP header `DPoP` MUST contain a valid DPoP proof.

The authorization server, after checking the validity of the token,
MUST associate the access token issued at the token endpoint with the
public key. It then sets `token_type` to `DPoP` in the token
response.

A client typically cannot know whether a certain AS supports DPoP. It
therefore SHOULD use the value of the `token_type` parameter returned
from the AS to determine support for DPoP: If the token type returned
is `Bearer` or another value, the AS does not support DPoP. If it is
`DPoP`, DPoP is supported. Only then, the client needs to send
the `DPoP` header in subsequent requests and use the token type
`DPoP` in the `Authorization` header as described below.

If a refresh token is issued to a public client at the token endpoint
and a valid DPoP proof is presented, the refresh token MUST be bound
to the public key contained in the header of the DPoP proof JWT.

If a DPoP-bound refresh token is to be used at the token endpoint by a
public client, the AS MUST ensure that the DPoP proof contains the
same public key as the one the refresh token is bound to. The access
token issued MUST be bound to the public key contained in the DPoP
proof.

# Resource Access (Proof of Possession for Access Tokens)

To make use of an access token that is token-bound to a public key
using DPoP, a client MUST prove the possession of the corresponding
private key by providing a DPoP proof in the `DPoP` request header.

The DPoP-bound access token must be sent in the `Authorization` header
with the prefix `DPoP`.

If a resource server detects that an access token that is to be used
for resource access is bound to a public key using DPoP (via the
methods described in (#Confirmation)) it MUST check that a header
`DPoP` was received in the HTTP request, and check the header's
contents according to the rules in (#checking).

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
Figure 4: Protected Resource Request with a DPoP sender-constrained access token.

# Public Key Confirmation {#Confirmation}

It MUST be ensured that resource servers can reliably identify whether
a token is bound using DPoP and learn the public key to which the
token is bound.

Access tokens that are represented as JSON Web Tokens (JWT) [@!RFC7519]
MUST contain information about the DPoP public key (in JWK format) in
the member `jkt` of the `cnf` claim, as shown in Figure 5.

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
Figure 5: Example access token body with `cnf` claim.

When access token introspection is used, the same `cnf` claim as above
MUST be contained in the introspection response.

Resource servers MUST ensure that the fingerprint of the public key in
the DPoP proof JWT equals the value in the `jkt` claim in the access
token or introspection response.

# Acknowledgements {#Acknowledgements}
      
We would like to thank David Waite, Filip Skokan, Mike Engan, and Justin Richer for
their valuable input and feedback.

This document resulted from discussions at the 4th OAuth Security
Workshop in Stuttgart, Germany. We thank the organizers of this
workshop (Ralf Küsters, Guido Schmitz).



# Security Considerations {#Security}

The prevention of token replay at a different
endpoint (see (#Objective_Replay_Different_Endpoint)) is achieved through
the binding of the DPoP proof to a certain URI and HTTP method.
However, DPoP does not achieve the same level of protection as, for
example, OAuth Mutual TLS [@I-D.ietf-oauth-mtls], as described in the
following.


## DPoP Proof Replay {#Token_Replay}

If an adversary is able to get hold of a DPoP proof JWT, the adversary
could replay that token at the same endpoint (the HTTP endpoint
and method are enforced via the respective claims in the JWTs). To
prevent this, servers MUST only accept DPoP proofs for a limited time
window after their `iat` time, preferably only for a brief period.
Servers SHOULD store the `jti` value of each DPoP proof for the time window in
which the respective DPoP proof JWT would be accepted and decline HTTP requests
for which the `jti` value has been seen before. In order to guard against 
memory exhaustion attacks a server SHOULD reject DPoP proof JWTs with unnecessarily
large `jti` values or store only a hash thereof.    

Note: To accommodate for clock offsets, the server MAY accept DPoP
proofs that carry an `iat` time in the near future (e.g., up to one
second in the future).

## Signed JWT Swapping

Servers accepting signed DPoP proof JWTs MUST check the `typ` field in the
headers of the JWTs to ensure that adversaries cannot use JWTs created
for other purposes in the DPoP headers.

## Signature Algorithms

Implementers MUST ensure that only digital signature algorithms that
are deemed secure can be used for signing DPoP proofs. In particular,
the algorithm `none` MUST NOT be allowed.

## Message Integrity {#request_integrity}

DPoP does not ensure the integrity of the payload or headers of
requests. The signature of DPoP proofs only contains the HTTP URI and
method, but not, for example, the message body or other request
headers.

This is an intentional design decision to keep DPoP simple to use, but
as described, makes DPoP potentially susceptible to replay attacks
where an attacker is able to modify message contents and headers. In
many setups, the message integrity and confidentiality provided by TLS
is sufficient to provide a good level of protection.

Implementers that have stronger requirements on the integrity of
messages are encouraged to either use TLS-based mechanisms or signed
requests. TLS-based mechanisms are in particular OAuth Mutual TLS
[@I-D.ietf-oauth-mtls] and OAuth Token Binding
[@I-D.ietf-oauth-token-binding].

Note: While signatures on (parts of) requests are out of the scope of
this specification, signatures or information to be signed can be
added into DPoP proofs.





# IANA Considerations {#IANA}
      
##  OAuth Access Token Type Registration

This specification registers the following access token type in the
OAuth Access Token Types registry defined in [RFC6749].

 * Type name: "DPoP"
 * Additional Token Endpoint Response Parameters: (none)
 * HTTP Authentication Scheme(s): Bearer
 * Change controller: IETF
 * Specification document(s): [[ this specification ]]


## JSON Web Signature and Encryption Type Values Registration

This specification registers the `dpop+jwt` type value in the IANA
JSON Web Signature and Encryption Type Values registry [@RFC7515]:

 * "typ" Header Parameter Value: "dpop+jwt"
 * Abbreviation for MIME Type: None
 * Change Controller: IETF
 * Specification Document(s): [[ this specification ]]

