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
OHTTP ({{!CHUNKED=I-D.ietf-ohai-chunked-ohttp}}) expands OHTTP to be
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

This document uses `SerializePublicKey()`, `DeserializePublicKey()`,
`GenerateKeyPair()`, `SetupBaseS()`, `SetupBaseR()`, `Export()`, `Seal()`,
and `Open()` from {{!HPKE=RFC9180}}.

# Mechanism

This mechanism relies on the generation of two more ephemeral key pairs per
OHTTP request: one for the client (denoted `skC, pkC`) and one for the
gateway (not denoted since it only exists inside of `SetupBaseS()`).

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
`DeserializePublicKey()` to parse the key then uses the HPKE receiver
context (`rctxt`) from the OHTTP request as follows:

1. Export a secret, `req_secret`, from `rctxt`, using the string
   "OHTTP PFS Request Derivation" as the `exporter_context` parameter to
   `context.Export`; see {{Section 5.3 of HPKE}}.  The length of this
   secret is `Nsecret`, the length of the shared secret for the KEM
   associated with `context`.

1. Build `info2` by concatenating the ASCII-encoded string
   "OHTTP PFS Response", a zero byte, the values of `key_id`, `kem_id`,
   `kdf_id`, and `aead_id`, as one 8-bit integer and three 16-bit
   integers, respectively, each in network byte order, and `req_secret`.

1. Create a sending HPKE context by invoking `SetupBaseS()`
   ({{Section 5.1.1 of HPKE}}) with the public key of the client `pkE`
   and `info2`.  This yields the context `sctxt2` and an encapsulation
   key `enc2`.

1. Encrypt `response` by invoking the `Seal()` method on `sctxt2`
   ({{Section 5.2 of HPKE}}) with empty associated data `aad`, yielding
   ciphertext `ct2`.

1. Concatenate `enc2` and `ct2`, yielding an Encapsulated Response,
   `enc_response`.

In pseudocode, this procedure is as follows:

~~~
req_secret = rctxt.Export("OHTTP PFS Request Derivation", Nsecret)
info2 = concat(encode_str("OHTTP PFS Response"),
               encode(1, 0),
               encode(1, key_id),
               encode(2, kem_id),
               encode(2, kdf_id),
               encode(2, aead_id),
               req_secret)
enc2, sctxt2 = SetupBaseS(pkC, info2)
ct2 = sctxt2.Seal("", response)
enc_response = concat(enc2, ct2)
~~~

The client then reverses this process to extract the response. To
decapsulate an Encapsulated Response, `enc_response`, it uses the HPKE
sender context (`sctxt`) from the OHTTP request as follows:

1. Parses `enc_request` into `enc2` and `ct2` (indicated using the function
   `parse()` in pseudocode). Note that `enc2` is of fixed-length, so there is
   no ambiguity in parsing this structure.

1. Export a secret, `req_secret`, from `sctxt`, using the string
   "OHTTP PFS Request Derivation" as the `exporter_context` parameter to
   `context.Export`; see {{Section 5.3 of HPKE}}.  The length of this
   secret is `Nsecret`, the length of the shared secret for the KEM
   associated with `context`.

1. Build `info2` by concatenating the ASCII-encoded string
   "OHTTP PFS Response", a zero byte, the values of `key_id`, `kem_id`,
   `kdf_id`, and `aead_id`, as one 8-bit integer and three 16-bit
   integers, respectively, each in network byte order, and `req_secret`.

1. Create a receiving HPKE context, `rctxt2`, by invoking `SetupBaseR()`
   ({{Section 5.1.1 of HPKE}}) with `skE`, `enc2`, and `info2`.

1. Decrypt `ct2` by invoking the `Open()` method on `rctxt2`
   ({{Section 5.2 of HPKE}}), with an empty associated data `aad`,
   yielding `response` or an error on failure.

In pseudocode, this procedure is as follows:

~~~
enc2, ct2 = parse(enc_response)
req_secret = sctxt.Export("OHTTP PFS Request Derivation", Nsecret)
info2 = concat(encode_str("OHTTP PFS Response"),
               encode(1, 0),
               encode(1, key_id),
               encode(2, kem_id),
               encode(2, kdf_id),
               encode(2, aead_id),
               req_secret)
rctxt2 = SetupBaseR(enc2, skE, info2)
response, error = rctxt2.Open("", ct2)
~~~

# Media Type

This mechanism uses a media type to differentiate the response from OHTTP
responses without this extension. The "message/ohttp-res-pfs" is used to
indicate that this extension is in use for the response.

Gateways MAY respond with "message/ohttp-res" responses and use the response
encoding described in {{Section 4.2 of OHTTP}} if it does not PFS to be useful
for the response. This allows saving computational resources, for example, if
the response is a generic response with an error status code where no part of
the response is tied to information in the request.

If chunked OHTTP {{CHUNKED}} is in use, the response media type for this
extension is "message/ohttp-chunked-res-pfs".

# Chunked OHTTP {#chunked}

Chunked OHTTP ({{CHUNKED}}) is different in that the client can send more data
after its first flight.

For the reponse, all chunks are encrypted by the gateway using the `sctxt2`
context and decrypted by the client using the `rctxt2` context, and using the
AAD construction described in {{CHUNKED}}.

For the request, there is a distinction between the first flight and
subsequent chunks. The first chunks are encrypted using `sctxt` as described
in {{CHUNKED}}. The client keeps using `sctxt` to send subsequent chunks
until is receives the first chunk from the gateway. Once the client receives
that, it creates `rctxt2` (see {{mechanism}}), and performs the following
steps to switch to it for sending:

1. Encrypt an empty chunk, the encrypted last first flight chunk `elff_chunk`
   with `sctxt` using empty associated data `aad`. Send this chunk with a
   variable-length integer length prefix.

1. Use that as the associated data `aad` to encrypt the first PFS chunk
   `sealed_pfs_chunk1` using `sctxt2`. Send that chunk with a
   variable-length integer length prefix.

1. Encrypt all subsequent non-final chunks with an empty AAD and a
   variable-length integer length prefix, using `sctxt2`.

1. Encrypt the final chunk with the AAD set to the ASCII-encoded
   string "final" and prefixed with a zero length, using `sctxt2`.

In pseudocode, this procedure is as follows:

~~~
elff_chunk = sctxt.Seal("", "")
elff_chunk_len = varint_encode(len(elff_chunk))
send(concat(elff_chunk_len, elff_chunk))
sealed_pfs_chunk1 = sctxt2.Seal(elff_chunk, pfs_chunk1)
sealed_pfs_chunk1_len = varint_encode(len(sealed_pfs_chunk1))
send(concat(sealed_pfs_chunk1_len, sealed_pfs_chunk1))
sealed_pfs_chunk2 = sctxt2.Seal("", pfs_chunk2)
sealed_pfs_chunk_len = varint_encode(len(sealed_pfs_chunk))
send(concat(sealed_pfs_chunk_len, sealed_pfs_chunk2))
...
sealed_final_chunk = sctxt2.Seal("final", chunk)
send(concat(varint_encode(0), sealed_final_chunk))
~~~

The gateway needs to handle this transition. It initially handles chunks using
the procedure from {{CHUNKED}}. When the gateway decrypts a chunk with a
zero-length plaintext, this means that the client is transitioning to the PFS
context (zero-length plaintext non-final chunks are explicitly disallowed in
chunked OHTTP without PFS, see {{Section 6 of CHUNKED}}).

When the gateway decrypts its first zero-length plaintext using the `rctxt`
context, it acts on the ciphertext `elff_chunk` as follows:

1. Save `elff_chunk` until the next chunk is received.

1. Wait for and parse the next variable-length integer length-prefixed
   chunk, `sealed_pfs_chunk1`.

1. Decrypt `sealed_pfs_chunk1` using `rctxt2` with the associated data `aad`
   set to `elff_chunk`.

1. Keep decrypting variable-length integer length-prefixed chunks with the
   associated data `aad` empty.

1. When encoutering a variable-length integer length-prefix set to zero,
   decrypt the final chunk using the associated data `aad` set to the
   ASCII-encoded string "final".

# Security Considerations {#sec}

The security considerations described in {{Section 6 of OHTTP}} and
{{Section 7 of CHUNKED}} apply to this document as well.

As mentioned in {{Section 7.2 of CHUNKED}}, interactivity can cause the
gateway to learn the round trip to the client. The PFS mechanism can
increase that risk if the client sends its last first flight chunk
(see {{chunked}}) immediately when it receives the gateway's first flight.
To avoid this, clients MUST NOT send their last first flight chunk until
they have more application data to send to the gateway.

# IANA Considerations

## OHTTP-PFS HTTP Header Field

This document requests IANA to register the following entry in the
"Hypertext Transfer Protocol (HTTP) Field Name Registry" maintained at
<[](https://www.iana.org/assignments/http-fields)>:

Field Name:
: OHTTP-PFS

Template:
: None

Status:
: provisional (permanent if this document is approved)

Reference:
: This document

Comments:

: None
{: spacing="compact"}

## Media Types

This document requests IANA to register the "message/ohttp-res-pfs" and
"message/ohttp-chunked-res-pfs" media types in the "Media Types Registry"
maintained at
<[](https://www.iana.org/assignments/media-types/media-types.xhtml)>.

The subtype names are "ohttp-res-pfs" and "ohttp-chunked-res-pfs",
respectively. The other fields have the following values:

Type name:

: message

Required parameters:

: N/A

Optional parameters:

: N/A

Encoding considerations:

: "binary"

Security considerations:

: see {{sec}}

Interoperability considerations:

: N/A

Published specification:

: This document

Applications that use this media type:

: Oblivious HTTP and applications that use Oblivious HTTP use this media type to
  identify encapsulated binary HTTP responses when using the PFS extension.

Fragment identifier considerations:

: N/A

Additional information:

: <dl spacing="compact">
  <dt>Magic number(s):</dt><dd>N/A</dd>
  <dt>Deprecated alias names for this type:</dt><dd>N/A</dd>
  <dt>File extension(s):</dt><dd>N/A</dd>
  <dt>Macintosh file type code(s):</dt><dd>N/A</dd>
  </dl>

Person and email address to contact for further information:

: see Authors' Addresses section

Intended usage:

: COMMON

Restrictions on usage:

: N/A

Author:

: see Authors' Addresses section

Change controller:

: IETF
{: spacing="compact"}

--- back

# Acknowledgments
{:numbered="false"}

Thank you to Martin Thomson for
[asking me](https://mailarchive.ietf.org/arch/msg/ohai/Vrh25BxK4wmIDJxeRYrYj6U1-g0/)
to write this draft, and to Chris Wood for
[supporting it](https://mailarchive.ietf.org/arch/msg/ohai/bLD_klUzBwVHUPeXI4a5NRIaoT8/)
 more than two years before it was written.

Thanks to Martin Thomson for reviewing this document.
