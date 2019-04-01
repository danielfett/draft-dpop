
{{introduction.md}}

# Main Objective {#Objective_Replay_Different_Endpoint}

Under the attacker model defined in [@I-D.ietf-oauth-security-topics],
the mechanism defined by this specification tries to ensure **token
replay at a different endpoint is prevented**.

More precisely, if an adversary is able to get hold of an access token
because it set up a counterfeit authorization server or resource
server, the adversary is not able to replay the respective access
token at another authorization or resource server.

Secondary objectives are discussed in (#Security).

# Concept

!---
~~~ ascii-art
+--------+                                              +---------------+
|        |--(A)-- Token Request (authorization grant)-->|               |
| Client |        (DPop-Binding/Proof)                  | Authorization |
|        |                                              |     Server    |
|        |<-(B)-- PoP Access Token ---------------------|               |
|        |        (token_type=pop)                      +---------------+
|        |        PoP Refresh Token for public clients
|        | 
|        |                                              +---------------+
|        |--(C)-- PoP Access Token -------------------->|               |
|        |        (DPoP-Proof)                          |    Resource   |
|        |                                              |     Server    |
|        |<-(D)-- Protected Resource -------------------|               |
|        |                                              +---------------+
+--------+
~~~
!---
Figure 1: Basic DPoP Flow

The new elements introduced by this specification are shown in Figure 1:

  * (A) In the Token Request, the client sends an authorization grant,
    e.g., an authorization code or a refresh token, to the
    authorization server in order to obtain an access token (and
    potentially a refresh token). The client proves the possession of
    a private key belonging to some public key by sending a request
    header containing a JWT that was signed using this private key.
    The matching public key is either sent in the request. <!-- or was
    already bound to the authotization grant. => PKCE -->
  * (B) The AS binds (sender-constrains) the access token to the
    public key claimed by the client; that is, the access token cannot
    be used without proving possession of the respective private key.
    This is signaled to the client by using the `token_type` value
    `bearer+dpop`. If a refresh token is issued to the client, it is
    sender-constrained in the same way if the client is a public
    client. Note: refresh tokens are automatically bound to the
    `client_id` of a confidential client, which is more flexible than
    binding it to a particular public key.
  * (C) If the client wants to use the access token, it has to prove
    possession of the private key by adding a header to the request
    that, again, contains a JWT signed with this private key. The JWT
    contains the endpoint URL and the request method. The resource
    server needs to receive information about which public key to
    check against. This information is either encoded directly into
    the access token, for JWT structured access tokens, or provided at
    the token introspection endpoint of the authorization server
    (request not shown).
  * (D) The resource server refuses to serve the request if the
    signature check fails or the data in the JWT do not match, e.g.,
    the request URI does not match the URI claim in the JWT.
  * Steps (A) and (B) can be repeated using a refresh token to obtain
    fresh access tokens. In this case, the client sends a DPoP proof
    JWT as in step (C) above. The client can optionally proof the
    possession of a new private/public key pair to which the new
    tokens are then bound by the authorization server. Otherwise, the
    authorization server binds the new tokens to the previously used
    public key.

The mechanism presented herein is not a client authentication method.
In fact, a primary use case are public clients (single page
applications) that do not use client authentication. Nonetheless, DPoP
is designed such that it is compatible with `private_key_jwt` and all
other client authentication methods.

Note: DPoP does not directly ensure message integrity but relies on
the TLS layer for that purpose.

# Token Request (Binding Tokens to a Public Key)

To bind a token to a public key in the token request, the client MUST
provide a public key and prove the possession of the corresponding
private key. The following HTTPS request illustrates the protocol for
this (with extra line breaks for display purposes only):


!---
~~~
POST /token HTTP/1.1
Host: server.example.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
DPoP-Binding: eyJhbGciOiJSU0ExXzUi ...

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
(remainder of JWK omitted for brevity)
~~~
!---
Figure 2: Token Request for a DPoP bound token.

The header `DPoP-Binding` MUST contain a JWT signed using the
private key chosen by the client. The header of the JWT contains
the following fields:

 * `typ`: with value `dpop_binding+jwt` (REQUIRED).
 * `jwk`: The public key chosen by the client, in JWK format
   (REQUIRED).

The body of the JWT contains the following fields:

 * `http_method`: The HTTP method for the request to which the JWT is
   attached, in upper case ASCII characters, as defined in [@!RFC7231]
   (REQUIRED).
 * `http_uri`: The HTTP URI used for the request, without query and
   fragment parts (REQUIRED).
 * `exp`: Expiration time of the JWT (REQUIRED). See [Security
   Considerations](#Security).
 * `jti`: Unique, freshly chosen identifier for this JWT (REQUIRED).
   SHOULD be used by the AS for replay detection and prevention. See
   [Security Considerations](#Security).

An example JWT is shown in Figure 3.

!---
```
{
    "typ": "dpop_binding+jwt",
    "alg": "ES512",
    "jwk": {
         "kty" : "EC",
         "kid" : "11",
         "crv" : "P-256",
         "x" : "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
         "y" : "3BttVivg+lSreASjpkttcsz+1rb7btKLv8EX4"
     }
}.{
    "jti": "HK2PmfnHKwXP",
    "http_method": "POST",
    "http_uri": "https://server.example.com/token",
    "exp": "..."
}
```
!---
Figure 3: Example JWT contents for `DPoP-Binding` header.

If the authorization server receives a `DPoP-Binding` header in a
token request, the authorization server MUST check that:

 1. the header value is a well-formed JWT,
 2. all required claims are contained in the JWT,
 3. the algorithm in the header of the JWT is supported by the
    application and deemed secure,
 4. the JWT is signed using the public key contained in the header of
    the JWT,
 5. the `typ` field in the header has the correct value,
 6. the `http_method` and `http_uri` claims match the respective values
    for the HTTP request in which the header was received,
 7. the token has not expired, and
 8. if replay protection is desired, that a JWT with the same `jti`
    value has not been received previously.

If these checks are successful, the authorization server MUST
associate the access token with the public key. It then sets
`token_type` to `bearer+dpop` in the token response. The client MAY
use the value of the `token_type` parameter to determine whether the
server supports the mechanisms specified in this document.

# Resource Access (Proof of Possession for Access Tokens)

To make use of an access token that is token-bound to a public key
using DPoP, a client MUST prove the possession of the corresponding
private key. More precisely, the client MUST create a JWT and sign it
using the previously chosen private key.

The JWT has the same format as above, except:

 * The header MUST contain a `typ` claim with the value
   `dpop_proof+jwt`.
 * The header SHOULD NOT contain a `jwk` field.
 
The signed JWT MUST then be sent in the `DPoP-Proof` request header.

If a resource server detects that an access token that is to be used
for resource access is bound to a public key using DPoP (via the
methods described in (#Confirmation)) it MUST check that:

 1. a header `DPoP-Proof` was received in the HTTP request, 
 2. the header's value is a well-formed JWT,
 3. all required claims are contained in the JWT,
 4. the algorithm in the header of the JWT is supported by the
    application and deemed secure,
 5. the JWT is signed using the public key to which the access token
    was bound,
 6. the `typ` field in the header has the correct value,
 7. the `http_method` and `http_uri` claims match the respective values
    for the HTTP request in which the header was received,
 8. the token has not expired, and
 9. if replay protection is desired, that a JWT with the same `jti`
    value has not been received previously.

If any of these checks fails, the resource server MUST NOT grant
access to the resource.

# Refresh Token Usage (Proof of Possession for Refresh Tokens)

At the token endpoint, public clients using a refresh token MUST
provide a proof of possession in the same way as for access tokens.

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
    "exp": 1493726400,
    "nbf": 1493722800,
    "cnf":{
        "dpop+jwk": {
            "kty" : "EC",
            "kid" : "11",
            "crv" : "P-256",
            "x" : "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
            "y" : "3BttVivg+lSreASjpkttcsz+1rb7btKLv8EX4"
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

 * Type name: "Bearer with DPoP"
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

This specification registers the `dpop_proof+jwt` and
`dpop_binding+jwt` type values in the IANA JSON Web Signature and
Encryption Type Values registry [@RFC7515]:

 * "typ" Header Parameter Value: "dpop_proof+jwt"
 * Abbreviation for MIME Type: None
 * Change Controller: IETF
 * Specification Document(s): [[ this specification ]]

 * "typ" Header Parameter Value: "dpop_binding+jwt"
 * Abbreviation for MIME Type: None
 * Change Controller: IETF
 * Specification Document(s): [[ this specification ]]



# Security Considerations {#Security}

The [Prevention of Token Replay at a Different
Endpoint](#Objective_Replay_Different_Endpoint) is achieved through
the binding of the DPoP JWT to a certain URI and HTTP method.


## Token Replay at the same authorization server

If an adversary is able to get hold of an DPoP-Binding JWT, it might
replay it at the authorization server's token endpoint with the same
or different payload. The issued access token is useless as long as
the adversary does not get hold of a valid DPoP-Binding JWT for the
corresponding resource server.

## Token Replay at the same resource server endpoint

If an adversary is able to get hold of a DPoP-Proof JWT, the adversary
could replay that token later at the same endpoint (the HTTP endpoint
and method are enforced via the respective claims in the JWTs). To
prevent this, clients MUST limit the lifetime of the JWTs, preferably
to a brief period. Furthermore, the `jti` claim in each JWT MUST
contain a unique (incrementing or randomly chosen) value, as proposed
in [@!RFC7253]. Resource servers SHOULD store values at least for the
lifetime of the respective JWT and decline HTTP requests by clients if
a `jti` value has been seen before.

## Signed JWT Swapping

Servers accepting signed DPoP JWTs MUST check the `typ` field in the
headers of the JWTs to ensure that adversaries cannot use JWTs created
for other purposes in the DPoP headers.

## Comparison to mTLS and OAuth Token Binding

  * mTLS stronger against intercepted connections
