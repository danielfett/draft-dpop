%%%
title = "OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer"
abbrev = "oauth-dpop"
ipr = "trust200902"
area = "Security"
workgroup = "Web Authorization Protocol"
keyword = ["security", "oauth2"]

date = 2019-04-02T12:00:00Z

[seriesInfo]
name = "Internet-Draft"
value = "draft-fett-oauth-dpop-02"
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
initials="J."
surname="Bradley"
fullname="John Bradley"
organization="Yubico"
    [author.address]
    email = "ve7jtb@ve7jtb.com"

[[author]]
initials="B."
surname="Campbell"
fullname="Brian Campbell"
organization="Ping Identity"
    [author.address]
    email = "bcampbell@pingidentity.com"

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

%%%

.# Abstract 

This document describes a mechanism for sender-constraining OAuth 2.0
tokens via a proof-of-possession mechanism on the application level.
This mechanism allows for the detection of replay attacks with access and refresh
tokens.

{mainmatter}

{{mainmatter.md}}
{{references.md}}

{backmatter}
{{documenthistory.md}}
