
{{introduction.md}}

# Main Objective {#Objective_Replay_Different_Endpoint}

Under the attacker model defined in [@I-D.ietf-oauth-security-topics],
the mechanism defined by this specification tries to ensure that token
replay at a different endpoint is prevented.

More precisely, if an adversary is able to get hold of an access token
because it set up a counterfeit authorization server or resource
server, the adversary is not able to replay the respective access
token at another authorization or resource server.

Secondary objectives are discussed in (#Security).

# Concept

The main data structure introduced by this specification is a DPoP
token. A client uses a DPoP token to prove the possession of a private
key belonging to a certain public key. Roughly speaking, a DPoP token
is a signature over some data of the request it is attached to (HTTP
URI and method) and a timestamp.

!---
~~~ ascii-art
+--------+                                          +---------------+
|        |--(A)-- Token Request ------------------->|               |
| Client |        (DPoP Token)                      | Authorization |
|        |                                          |     Server    |
|        |<-(B)-- PoP Access Token -----------------|               |
|        |        (token_type=Bearer-DPoP)          +---------------+
|        |        PoP Refresh Token for public clients
|        | 
|        |                                          +---------------+
|        |--(C)-- PoP Access Token ---------------->|               |
|        |        (DPoP Token)                      |    Resource   |
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
    token to the request in a HTTP header.
  * (B) The AS binds (sender-constrains) the access token to the
    public key claimed by the client in the DPoP token; that is, the access token cannot
    be used without proving possession of the respective private key.
    This is signaled to the client by using the `token_type` value
    `Bearer-DPoP`. 
  * If a refresh token is issued to a public client, it is
    sender-constrained in the same way. For confidential clients,
    refresh tokens are bound to the `client_id`, which is more
    flexible than binding it to a particular public key.
  * (C) If the client wants to use the access token, it has to prove
    possession of the private key by adding a header to the request
    that, again, contains a DPoP token. The resource server needs to
    receive information about which public key to check against. This
    information is either encoded directly into the access token, for
    JWT structured access tokens, or provided at the token
    introspection endpoint of the authorization server (request not
    shown).
  * (D) The resource server refuses to serve the request if the
    signature check fails or the data in the DPoP token do not match,
    e.g., the request URI does not match the URI claim in the DPoP
    token.
  * When a refresh token that is sender-constrained using DPoP is used
    by the client, the client has to provide a DPoP token just as in
    the case of a resource access. The new access token will be bound
    to the same public key.

The mechanism presented herein is not a client authentication method.
In fact, a primary use case are public clients (single page
applications) that do not use client authentication. Nonetheless, DPoP
is designed such that it is compatible with `private_key_jwt` and all
other client authentication methods.

Note: DPoP does not directly ensure message integrity but relies on
the TLS layer for that purpose.

# DPoP Tokens

DPoP uses so-called DPoP tokens for binding public keys and proving
knowledge about private keys.

## Syntax

A DPoP token is a JWT ([@!RFC7519]) that is signed (using JWS,
[@!RFC7515]) using a private key chosen by the client (see below). The
header of a DPoP JWT contains at least the following fields:

 * `typ`: type header, value `dpop+jwt` (REQUIRED).
 * `alg`: a digital signature algorithm identifier as per [@!RFC7518]
   (REQUIRED). MUST NOT be `none` or an identifier for a symmetric
   algorithm (MAC).

The body of a DPoP token contains at least the following fields:

 * `jti`: Unique identifier for this JWT chosen freshly when creating
   the DPoP token (REQUIRED). SHOULD be used by the AS for replay
   detection and prevention. See [Security Considerations](#Security).
 * `http_method`: The HTTP method for the request to which the JWT is
   attached, as defined in [@!RFC7231] (REQUIRED).
 * `http_uri`: The HTTP URI used for the request, without query and
   fragment parts (REQUIRED).
 * `exp`: Expiration time of the JWT (REQUIRED). See [Security
   Considerations](#Security).
* `cnf`: Confirmation claim as per [@!RFC7800] containing a member
   `dpop+jwk`, representing the public key chosen by the client in JWK
   format (REQUIRED).


An example DPoP token is shown in Figure 2.

!---
```
{
    "typ": "dpop+jwt",
    "alg": "ES256"
}.{
    "jti": "HK2PmfnHKwXP",
    "http_method": "POST",
    "http_uri": "https://server.example.com/token",
    "exp": 1555555555,
    "cnf":{
        "dpop+jwk": {
             "kty": "EC",
             "crv": "P-256",
             "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
             "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        }
    }
}
```
!---
Figure 2: Example JWT contents for `DPoP` header.

Note: To keep DPoP simple to implement, only the HTTP method and URI
are signed in DPoP tokens. Nonetheless, DPoP tokens can be extended to
contain other information of the HTTP request (see also
(#request_integrity)).

## Checking DPoP tokens {#checking}

To check if a string that was received as part of an HTTP Request is a
valid DPoP token, the receiving server MUST ensure that

 1. the string value is a well-formed JWT,
 1. all required claims are contained in the JWT,
 1. the `typ` field in the header has the value `dpop+jwt`,
 1. the algorithm in the header of the JWT designates a digital
    signature algorithm, is not `none`, is supported by the
    application, and is deemed secure,
 1. that the JWT is signed using the public key contained in the `cnf`
    claim of the JWT,
 1. if a DPoP sender-constrained refresh token is to be used at the
    token endpoint, that the JWT is signed using the public key the
    refresh token is bound to,
 1. if a DPoP sender-constrained access token is to be used at the
    resource endpoint, that the JWT is signed using the public key the
    access token is bound to (see below),
 1. the `http_method` claim matches the respective value for the HTTP
    request in which the JWT was received (case-insensitive),
 1. the `http_uri` claims matches the respective value for the HTTP
    request in which the JWT was received, ignoring any query and
    fragment parts,
 1. the token has not expired, and
 1. if replay protection is desired, that a JWT with the same `jti`
    value has not been received previously.

Servers SHOULD employ Syntax-Based Normalization and Scheme-Based
Normalization in accordance with Section 6.2.2. and Section 6.2.3. of
[@!RFC3986] before comparing the `http_uri` claim.


# Token Request (Binding Tokens to a Public Key)

To bind a token to a public key in the token request, the client MUST
provide a valid DPoP token in a `DPoP` header. The HTTPS request shown
in Figure 3 illustrates the protocol for this (with extra line breaks
for display purposes only).


!---
~~~
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
DPoP: eyJhbGciOiJSU0ExXzUi ...

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
~~~
!---
Figure 3: Token Request for a DPoP sender-constrained token.

The HTTP header `DPoP` MUST contain a valid DPoP token.

If the token is valid, the authorization server MUST associate the
access token issued at the token endpoint with the public key. It then
sets `token_type` to `Bearer-DPoP` in the token response. The client
MAY use the value of the `token_type` parameter to determine whether
the server supports the mechanisms specified in this document.

If a refresh token is issued to a public client at the token endpoint
and a valid DPoP token is presented, the refresh token MUST be bound
to the public key contained in the DPoP token.

If a DPoP-bound refresh token is to be used at the token endpoint by a
public client, the AS MUST ensure that the DPoP token contains the
same public key as the one the refresh token is bound to. The access
token issued MUST be bound to the public key contained in the DPoP
token.

# Resource Access (Proof of Possession for Access Tokens)

To make use of an access token that is token-bound to a public key
using DPoP, a client MUST prove the possession of the corresponding
private key by providing a DPoP token in the `DPoP` request header.

If a resource server detects that an access token that is to be used
for resource access is bound to a public key using DPoP (via the
methods described in (#Confirmation)) it MUST check that a header
`DPoP` was received in the HTTP request, and check the header's
contents according to the rules in (#checking).

If (and only if) all checks are successful, the resource server MAY
grant access to the resource.

# Public Key Confirmation {#Confirmation}

It MUST be ensured that resource servers can reliably identify whether
a token is bound using DPoP and learn the public key to which the
token is bound.

Access tokens that are represented as JSON Web Tokens (JWT)[@!RFC7519]
MUST contain information about the DPoP public key (in JWK format) in
the member `dpop+jwk` of the `cnf` claim, as shown in Figure 4.

!---
```
{
    "iss": "https://server.example.com",
    "sub": "something@example.com",
    "exp": 1503726400,
    "nbf": 1503722800,
    "cnf":{
        "dpop+jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        }
    }
}
```
!---
Figure 4: Example access token body with `cnf` claim.

When access token introspection is used, the same `cnf` claim as above
MUST be contained in the introspection response.


# Acknowledgements {#Acknowledgements}
      
<!-- We would like to thank [...] for their valuable feedback. -->

This document resulted from discussions at the 4th OAuth Security
Workshop in Stuttgart, Germany. We thank the organizers of this
workshop (Ralf Küsters, Guido Schmitz).


# IANA Considerations {#IANA}
      
##  OAuth Access Token Type Registration

This specification registers the following access token type in the
OAuth Access Token Types registry defined in [RFC6749].

 * Type name: "Bearer-DPoP"
 * Additional Token Endpoint Response Parameters: (none)
 * HTTP Authentication Scheme(s): Bearer
 * Change controller: IETF
 * Specification document(s): [[ this specification ]]


## JWT Confirmation Methods Registration

This specification requests registration of the following value in
the IANA "JWT Confirmation Methods" registry [IANA.JWT.Claims] for
JWT "cnf" member values established by [@RFC7800].

 *  Confirmation Method Value: "dpop+jwk"
 *  Confirmation Method Description: JWK encoded public key for dpop proof token
 *  Change Controller: IESG
 *  Specification Document(s): [[ this specification ]]
 
<!--
## OAuth Parameters Registry

This specification registers the following parameters in the IANA
"OAuth Parameters" registry defined in OAuth 2.0 [@RFC6749].

 * Parameter name: dpop_binding
 * Parameter usage location: token request
 * Change controller: IESG
 * Specification document(s): [[ this specification ]]

 * Parameter name: dpop_proof
 * Parameter usage location: token request
 * Change controller: IESG
 * Specification document(s): [[ this specification ]]
-->

## JSON Web Signature and Encryption Type Values Registration

This specification registers the `dpop+jwt` type value in the IANA
JSON Web Signature and Encryption Type Values registry [@RFC7515]:

 * "typ" Header Parameter Value: "dpop+jwt"
 * Abbreviation for MIME Type: None
 * Change Controller: IETF
 * Specification Document(s): [[ this specification ]]


# Security Considerations {#Security}

The [Prevention of Token Replay at a Different
Endpoint](#Objective_Replay_Different_Endpoint) is achieved through
the binding of the DPoP JWT to a certain URI and HTTP method.


## DPoP Token Replay

If an adversary is able to get hold of a DPoP token, the adversary
could replay that token later at the same endpoint (the HTTP endpoint
and method are enforced via the respective claims in the JWTs). To
prevent this, clients MUST limit the lifetime of the JWTs, preferably
to a brief period. Furthermore, the `jti` claim in each JWT MUST
contain a unique (incrementing or randomly chosen) value, as proposed
in [@!RFC7253]. Resource servers SHOULD store values at least for the
lifetime of the respective JWT and decline HTTP requests by clients if
a `jti` value has been seen before.

## Signed JWT Swapping

Servers accepting signed DPoP tokens MUST check the `typ` field in the
headers of the JWTs to ensure that adversaries cannot use JWTs created
for other purposes in the DPoP headers.

## Signature Algorithms

Implementers MUST ensure that only digital signature algorithms that
are deemed secure can be used for signing DPoP tokens. In particular,
the algorithm `none` MUST NOT be allowed.

## Message Integrity {#request_integrity}

DPoP does not ensure the integrity of the payload or headers of
requests. The signature of DPoP tokens only contains the HTTP URI and
method, not, for example, the message body or other request headers.

This is an intentional design decision to keep DPoP simple to use, but
as described, makes DPoP potentially susceptible to replay attacks
where an attacker is able to modify message contents and headers. In
many setups, the message integrity and confidentiality provided by TLS
is sufficient to provide a reasonable level of protection.

Implementers that have stronger requirements on the integrity of
messages are encouraged to either use TLS-based mechanisms or signed
requests. TLS-based mechanisms are in particular OAuth Mutual TLS
[@I-D.ietf-oauth-mtls] and OAuth Token Binding
[@I-D.ietf-oauth-token-binding].

Note: While signatures on (parts of) requests are out of the scope of
this specification, signatures or information to be signed can be
added into DPoP tokens.

