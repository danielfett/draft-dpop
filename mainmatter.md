
{{introduction.md}}

# Concept

The mechanism defined by this document works as follows:

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
| Client |       (req_cnf)               | Authorization |
|        |                               |     Server    |
|        |<-(D)-- PoP Access Token ------|               |
|        |       (token_type=pop)        +---------------+
|        |        PoP Refresh Token
|        |                               +---------------+
|        |--(E)-- PoP Refresh Token ---->|               |
|        |   (with proof of private key) | Authorization |
|        |                               |     Server    |
|        |<-(F)-- PoP Access Token ------|               |
|        |       (token_type=pop)        +---------------+
|        |
|        |                               +---------------+
|        |--(G)-- PoP Access Token ----->|               |
|        |   (with proof of private key) |    Resource   |
|        |                               |     Server    |
|        |<-(H)--- Protected Resource ---|               |
+--------+                               +---------------+
~~~
!---
Figure 1: Basic DPoP Flow

The new elements introduced by this specification are shown in Figure 1:

  * In the Token Request (C), the client proves the possession of a
    private key belonging to some public key by using the private key
    to sign the authorization code. The matching public key is either
    sent in the same request (for public or confidential clients) or
    available to the AS and RS via a JWKS URI registered during the
    client registration (for confidential clients).
  * The AS binds (sender-constrains) the access token to the public
    key claimed by the client; that is, the access token cannot be
    used without proving possession of the respective private key.
    This is signalled to the client by using the `token_type` value
    `pop` (for proof-of-possession). If a refresh token is issued to
    the client, it is sender-constrained in the same way.
  * If the client wants to use the refresh token (E) or the access
    token (G), it has to prove possession of the private key by
    signing a message containing the respective token, the endpoint
    URL, and the request method. This signature is provided as a
    signed JWT.
  * In the case of the refresh token, the AS can immediately check
    that the JWT was signed using the matching private key claimed in
    request (C). 
  * In the case of the access token, the resource server needs receive
    information about which public key to check against (either a key
    value or a JWK URI, depending on the option chosen in the token
    request). This information is either encoded directly into the
    access token, for JWT structured access tokens, or at the token
    introspection endpoint of the authorization server (request not
    shown).

# Token Request (Binding Public Keys)
For binding a public key in the token request, there are two options:
direct binding (client provides public key and proves the possession
of the private key) or indirect binding (client proves possession of a
private key contained in the client's JWKS provided at client
registration time. 

Direct binding is available to all types of clients, indirect
binding is only available to confidential clients.

In both cases, the client makes the following HTTPS request (extra
line breaks are for display purposes only):


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
chosen by the client. The contents of the JWT contained in `req_cnf`
are different for direct binding and indirect binding, as described
in the following.

## Direct Binding

In this case, the client choses a fresh asymmetric key pair before
issuing the token request. It then adds the public key to the
header of the `req_cnf` JWT.

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

[ Do we want to allow `jku` here? ]
## Indirect Binding

In this case, the client choses a key from its published JWK key set
available at the URL that the client registered during client
registration with the AS. The JWT refers to this key using the `kid`
claim in the header of the JWT.

!---
```
{
    "kid" : h'11',
}.{
    "code": "SplxlOBeZQQYbYS6WxSbIA"
}
```
!---
Figure 4: JWT for `req_cnf` parameter with indirect binding.

[ Is this a valid usage for `kid`? ]


# Resource Access (Proof of Possession for Access Tokens)

Create JWT:

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
    
`at_hash` like in OIDC.

Send this JWT in `cnf` header?

## Public Key Confirmation with Direct Binding

When access tokens are represented as JSON Web Tokens (JWT)[RFC7519],
information about the DPoP public key SHOULD be represented using the
`dpop:jwk` confirmation method member defined herein.

```
{
    "iss": "https://server.example.com",
    "sub": "ty.webb@example.com",
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

## Public Key Confirmation with Indirect Binding

[ Two options: include JWK URI and kid into a claim `dpop:jwk_uri`; or copy the whole key into `cnf` claim ]

[ Advantage of the second option: it is harder or impossible to exchange the key on the server ]

# Acknowledgements {#Acknowledgements}
      
We would like to thank [...] for their valuable feedback.
    

# IANA Considerations {#IANA}
      
  This draft includes no request to IANA.
    

# Security Considerations {#Security}
      
[ todo ]

  * The contents of JWK URIs might change; the key for which the possession is proven in the token request might not be the same against which the AT is later checked.
  * AS/RS MUST check `typ` in JWTs!
  * Actually sender-constraining access tokens (or any token which is not one-time use) without introducing a state is not possible.
  * Using time for AT pop token enables precomputing attacks
  * mTLS stronger against intercepted connections
  * 
