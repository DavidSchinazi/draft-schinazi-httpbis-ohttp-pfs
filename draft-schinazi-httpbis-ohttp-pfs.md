---
title: "A Perfect Forward Secure Extension to Oblivious HTTP"
abbrev: "Perfect Forward Secure OHTTP"
category: std
docname: draft-schinazi-httpbis-ohttp-pfs-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - oblivious
 - HTTP
 - configuration
 - extension
area: "Web and Internet Transport"
workgroup: "HTTP"
venue:
  group: "HTTP"
  type: "Working Group"
  home: https://httpwg.org/
  mail: "ietf-http-wg@w3.org"
  arch: "https://lists.w3.org/Archives/Public/ietf-http-wg/"
  github: "DavidSchinazi/draft-schinazi-httpbis-ohttp-pfs"
  latest: "https://DavidSchinazi.github.io/draft-schinazi-httpbis-ohttp-pfs/draft-schinazi-httpbis-ohttp-pfs.html"

author:
 -
    ins: D. Schinazi
    name: David Schinazi
    org: Google LLC
    email: dschinazi.ietf@gmail.com

normative:

informative:

...

--- abstract

Oblivious HTTP (OHTTP) is a protocol for forwarding encrypted HTTP messages.
It does not provide Perfect Forward Secrecy (PFS). Chunked OHTTP expands
OHTTP to be suitable for longer-lived streams, but still does not offer PFS.
Combined, this is leading sensitive traffic to de deployed at scale without
PFS. This document proposes a solution.

--- middle

# Introduction

Oblivious HTTP ({{!OHTTP=RFC9458}}) is a protocol for forwarding encrypted
HTTP messages. It does not provide Perfect Forward Secrecy (PFS). Chunked
OHTTP ({{?CHUNKED=I-D.ietf-ohai-chunked-ohttp}}) expands OHTTP to be
suitable for longer-lived streams, but still does not offer PFS.

Unfortunately, providing a streaming abstraction over OHTTP makes it an
attractive tool to provide privacy. This is leading application designers
to build Remote Procedure Call (RPC) systems over this bidirectional
stream, without realizing the security cost of losing PFS.

This document proposes a solution that offers PFS to all data sent over
OHTTP apart from the client's first flight. This provides privacy and
security properties similar to TLS 0-RTT (see {{Section 2.3 of ?TLS=RFC8446}})
run over HTTP CONNECT (see {{Section 9.3.6 of ?HTTP=RFC9110}})
without losing the performance nor request-correlation-prevention
properties of OHTTP.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Mechanism

This section is currently a work in progress. Please see the
[editor's copy](https://davidschinazi.github.io/draft-schinazi-httpbis-ohttp-pfs/draft-schinazi-httpbis-ohttp-pfs.html).

# Security Considerations

TODO

# IANA Considerations

TODO

--- back

# Acknowledgments
{:numbered="false"}

Thank you to Martin Thomson and Chris Wood for
[asking](https://mailarchive.ietf.org/arch/msg/ohai/Vrh25BxK4wmIDJxeRYrYj6U1-g0/)
[me](https://mailarchive.ietf.org/arch/msg/ohai/AAWH6Cp3OmxwEuzoxehYFh1O4ck/)
to write this draft.
