# OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer

This document defines an application-level sender-constraint mechanism for
OAuth 2.0 access tokens and refresh tokens that can be applied when neither mTLS nor
OAuth Token Binding are utilized. It achieves proof-of-possession using
a public/private key pair.

Written in markdown for the [mmark processor](https://github.com/mmarkdown/mmark).

## Compiling

### using Docker
From the root of this repository, run
```bash
docker run -v `pwd`:/data danielfett/markdown2rfc
```
(see https://github.com/oauthstuff/markdown2rfc)

### without Docker
compile using mmark and xml2rfc: `mmark main.md > draft.xml; xml2rfc --html draft.xml`
