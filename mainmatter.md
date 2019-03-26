
{{introduction.md}}

# Concept


!---
~~~ ascii-art
+--------+                               +---------------+
|        |--(A)- Authorization Request ->|   Resource    |
|        |                               |     Owner     |
|        |<-(B)-- Authorization Grant ---|               |
|        |                               +---------------+
|        |
|        |                               +---------------+
|        |--(C)-- Token Request -------->|               |
| Client |        (req_cnf)              | Authorization |
|        |                               |     Server    |
|        |<-(D)-- PoP Access Token ------|               |
|        |        (token_type=pop)       +---------------+
|        |        PoP Refresh Token for public clients
|        | 
|        |                               +---------------+
|        |--(E)-- PoP Access Token ----->|               |
|        |   (with proof of private key) |    Resource   |
|        |                               |     Server    |
|        |<-(F)--- Protected Resource ---|               |
|        |                               +---------------+
|        |
|        | public client refresh token usage:
|        |                               +---------------+
|        |--(G)-- PoP Refresh Token ---->|               |
|        |   (with proof of private key) | Authorization |
|        |                               |     Server    |
|        |<-(H)-- PoP Access Token ------|               |
|        |       (token_type=pop)        +---------------+
|        |
+--------+
~~~
!---
Figure 1: Basic DPoP Flow

The new elements introduced by this specification are shown in Figure 1:

  * In the Token Request (C), the client proves the possession of a
    private key belonging to some public key by using the private key
    to sign the authorization code. The matching public key is sent in
    the same request.
  * The AS binds (sender-constrains) the access token to the public
    key claimed by the client; that is, the access token cannot be
    used without proving possession of the respective private key.
    This is signalled to the client by using the `token_type` value
    `pop` (for proof-of-possession). If a refresh token is issued to
    the client, it is sender-constrained in the same way if the client
    is a public client and thus is not able to authenticate requests
    to the token endpoint.
  * If the client wants to use the access token (E) or the (public)
    client wants to use a refresh token, the client has to prove
    possession of the private key by signing a message containing the
    respective token, the endpoint URL, and the request method. This
    signature is provided as a signed JWT.
  * In the case of the refresh token, the AS can immediately check
    that the JWT was signed using the matching private key claimed in
    request (C). 
  * In the case of the access token, the resource server needs to
    receive information about which public key to check against. This
    information is either encoded directly into the access token, for
    JWT structured access tokens, or provided at the token
    introspection endpoint of the authorization server (request not
    shown).

# Token Request (Binding Public Keys)

To bind a public key in the token request, the client provides public
key and proves the possession of the corresponding private key.

To this end, the client makes the following HTTPS request (extra line
breaks are for display purposes only):


!---
~~~
POST /token HTTP/1.1
Host: server.example.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded;charset=UTF-8

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
&token_type=pop
&req_cnf=eyJhbGciOiJSU0ExXzUi ...
(remainder of JWK omitted for brevity)
~~~
!---
Figure 2: Token Request for a DPoP bound token.

[ How do we indicate DPoP? token type? ]

The parameter `req_cnf` contains a JWT signed using the asymmetric key
chosen by the client. The JWT contains the `code` value. The header of
the JWT contains the public key chosen by the client:

!---
```
{
    "typ": "pop+jwt",
    "jwk": {
         "kty" : "EC",
         "kid" : h'11',
         "crv" : "P-256",
         "x" : b64'usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8',
         "y" : b64'IBOL+C3BttVivg+lSreASjpkttcsz+1rb7btKLv8EX4'
     }

}.{
    "code": "SplxlOBeZQQYbYS6WxSbIA"
}
```
!---
Figure 3: JWT for `req_cnf` parameter with direct binding.

# Resource Access (Proof of Possession for Access Tokens)

To prove the possession of the private key when using the access
token, the client creates a JWT as shown in Figure 4 and signs it
using the previously chosen private key.

!---
```
{
    "typ": "pop+jwt",
    "alg": "ES512"
}.
{
    "at_hash": "2ba9eddc1f91394e57f9f8",
    "http_method": "get",
    "http_uri": "https://resource-server.example.com?path=something",
    "exp": "...",
}
```
!---
Figure 4: Proof-of-Possession JWT 

This JWT contains the following fields:

 * `at_hash`: [access token hash as in OIDC]
 * `http_method`: The HTTP method used for the resource access
 * `http_uri`: The HTTP URI used for the resource access
 * `exp`: Expiration time of the JWT. The lifetime should be short.

The signed JWT is then sent in the `Authorization-Confirmation` HTTP
header. [ Can we come up with a better header name? ]

## Public Key Confirmation 

When access tokens are represented as JSON Web Tokens (JWT)[RFC7519],
information about the DPoP public key SHOULD be represented using the
`jwk+dpop` confirmation method member defined herein.

```
{
    "iss": "https://server.example.com",
    "sub": "something@example.com",
    "exp": 1493726400,
    "nbf": 1493722800,
    "cnf":{
        "jwk+dpop": {
            "kty" : "EC",
            "kid" : h'11',
            "crv" : "P-256",
            "x" : b64'usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8',
            "y" : b64'IBOL+C3BttVivg+lSreASjpkttcsz+1rb7btKLv8EX4'
        }
    }
}
```

When access token introspection is used, the same `cnf` claim as above
is contained in the introspection response.


# Acknowledgements {#Acknowledgements}
      
We would like to thank Torsten Lodderstedt, [...] for their valuable feedback.
    

# IANA Considerations {#IANA}
      
  This draft includes no request to IANA.
    

# Security Considerations {#Security}
      
[ todo ]

  * AS/RS MUST check `typ` in JWTs!
  * Actually sender-constraining access tokens (or any token which is not one-time use) without introducing a state is not possible.
  * Using time for AT pop token enables precomputing attacks
  * mTLS stronger against intercepted connections
  * 
