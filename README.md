# OAuth 2.0 Demonstration of Proof-of-Possession at the Application-layer

This document outlines an application-level sender-constraining for
access tokens and refresh tokens that can be used if neither mTLS nor
OAuth Token Binding are available. It uses proof-of-possession based on
a public/private key pair.

Written in markdown for the [mmark processor](https://github.com/mmarkdown/mmark).

Compiling: `mmark -2 main.md > draft.xml; xml2rfc --legacy --html draft.xml`
