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
properties of OHTTP. This mechanism is designed to be backwards compatible
with unextended OHTTP.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses terminology from {{!HPKE=RFC9180}}.

# Mechanism

This mechanism relies on the generation of two more ephemeral key pairs per
OHTTP request: one for the client (denoted `skC, pkC`) and one for the
gateway (not denoted since it only exists inside of `SetupBaseS`).

The client starts by generating a second ephemeral key pair, using the same KEM
it has selected for this request:

~~~
skC, pkC = GenerateKeyPair()
~~~

The client then adds the serialized public key
`SerializePublicKey(pkC)` to its Binary HTTP ({{!BHTTP=RFC9292}})
request headers using the "OHTTP-PFS" header. That header is a
Structured Header Field Item of type Byte Sequence as defined in
{{Section 3.3.5 of !STRUCTURED=RFC9651}}. For example:

~~~
ohttp-pfs: :dGhpcyBpcyBhIHB1YmxpYyBrZXk=:
~~~

The client then encrypts the Binary HTTP request following the procedure in
{{Section 4.3 of OHTTP}}. The gateway follows the procedure in that same
section to recover the Binary HTTP request.

The gateway then checks the request for the presence of the "ohttp-pfs"
header to determine whether this extension is in use. If it is, it uses
the HPKE receiver context (`rctxt`) from the OHTTP request as the HPKE
context (`req_context`) as follows:

~~~
req_secret = req_context.Export("OHTTP PFS Request Derivation",
                                max(Nn, Nk))
info2 = concat(encode_str("OHTTP PFS Response"),
               encode(1, 0),
               encode(1, key_id),
               encode(2, kem_id),
               encode(2, kdf_id),
               encode(2, aead_id),
               req_secret)
enc2, pctxt = SetupBaseS(pkC, info2)
ct2 = pctxt.Seal("", response)
enc_response = concat(enc2, ct2)
~~~

The client then reverses this process to extract the response.

This document's editor ran out of time right before the draft deadline, so
this section is still a work in progress. Please check the
[editor's copy](https://davidschinazi.github.io/draft-schinazi-httpbis-ohttp-pfs/draft-schinazi-httpbis-ohttp-pfs.html),
they most likely have made some progress since then.

# Security Considerations

TODO

# IANA Considerations

## OHTTP-PFS HTTP Header Field

TODO

--- back

# Acknowledgments
{:numbered="false"}

Thank you to Martin Thomson and Chris Wood for
[asking](https://mailarchive.ietf.org/arch/msg/ohai/Vrh25BxK4wmIDJxeRYrYj6U1-g0/)
[me](https://mailarchive.ietf.org/arch/msg/ohai/AAWH6Cp3OmxwEuzoxehYFh1O4ck/)
to write this draft.
