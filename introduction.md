# Introduction {#Introduction}

[@I-D.ietf-oauth-mtls] describes methods to bind (sender-constrain) access tokens
using mutual Transport Layer Security (TLS) authentication with X.509
certificates. 

[@I-D.ietf-oauth-token-binding] provides mechanisms to
sender-constrain access tokens using HTTP token binding.

Due to a sub-par user experience of TLS client authentication in user
agents and a lack of support for HTTP token binding, neither mechanism
can be used if an OAuth client is a Single Page Application (SPA)
running in a web browser.

This document outlines an application-level sender-constraining for
access and refresh tokens that can be used in cases where neither mTLS nor
OAuth Token Binding are available. It uses proof-of-possession based on
a public/private key pair and application-level signing.

DPoP can be used with public clients and, in case of confidential
clients, can be combined with any client authentication method.

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
