# Solana Transport Layer

The STL (Solana Transport Layer) is a partial redesign of the Solana
peer-to-peer network stack from first principles, with a focus on
security and high performance.

It includes a connection-less application transport that provides
authentication and (optionally) encryption to undirectional UDP
datagram flows.  Authentication is provided via a separate handshake
protocol, which can simultaneously secure multiple applications.

The protocols are carefully designed to minimize protocol complexity
and strictly bound compute and memory requirements.  The STL protocol
specifications include implementation guidance to assist with security
hardening and hardware offload.

STL features authenticated encryption using standard modern
cryptography, as used in the [Noise Protocol] and [TLS 1.3].

  [Noise Protocol]: http://www.noiseprotocol.org/noise.html
  [TLS 1.3]: https://datatracker.ietf.org/doc/html/rfc8446

> **The acronym STL is deliberately annoying to discourage production**
> **use before finalization of the protocol.  If chosen for adoption,**
> **it is to be renamed by a Solana community vote.**

## 1. Requirements

We define a base set of requirements realized using the simple
mode.  A superset including stretch goals is realized using the
encrypted mode.

### 1.1. Application layer base requirements

STL serves to improve the safety and reliability for UDP datagram
transmissions over the public Internet.

At a high level, STL aims to provide the following properties:

- Protection against malicious packet injection through spoofing of
  the source IP address.
- Protection against common Denial-of-Service (DoS) vulnerabilities,
  such as traffic amplification and volumetric flood attacks.
- High performance as a function of robustness.
- Deployment flexibility by establishing authentication and (optionally)
  encryption keys via a separate out of-band protocol.

STL specifically aims to improve communication in Internet peer-to-peer
networks consisting of widely available home server and data center
hardware.  Consequently, we aim to support the following technical
capabilities:

- IP datagram abstraction: To support high performance networking
  over the Internet, the transport layer assumes unicast UDP traffic.
  Packet information is transparently exposed to the upper layer
  without reordering data.  Application packet processing is
  connection-less:  Processing an application packet does not depend
  on information gathered from an earlier aplication packet.
  Instead, the only dependency is external session data gathered
  from the handshake protocol.

- Simple source IP authentication: Use plaintext ephemeral session
  IDs to protect against IP spoofing attacks and some forms of
  payload injection.  Negotiation of session IDs is provided by the
  handshake protocol.  Protection against eavesdroppers is separately
  provided in the encrypted mode.

- Uni/bidirectional mode: Support efficient multicast-over-unicast
  (e.g. Solana Turbine protocol) in unidirectional mode.
  Bidirectional mode is simply achieved via two unidirectional
  sessions in opposing directions.

- Throughput: In software-only mode, achieve a per-core application
  throughput at 90% of memory bandwidth in simple mode.
  In encrypted mode, achieve 20-40 Gbps per-core performance on
  Icelake Server.

  > **TODO**: These figures are guesses. Further testing is required

- eBPF/SmartNIC offload: Support high performance packet filtering
  using the Linux XDP interface.  Support both software and hardware-
  accelerated mode using off-the-shelf "smart NICs".

- Hardware offload: Support heterogenous architectures, such as
  packet filtering on network-attached or accelerator-style FPGAs,
  and

- External DDoS protection: Provide a concept for protection against
  volumetric attacks using external firewall hardware.  Review the
  effectiveness of generic UDP firewall hardware versus a custom
  solution.

### 1.2. Handshake layer base requirements

STL also defines a handshake protocol which is used to request
sessions from a server.  The handshake protocol is the first
destination of any new client, and thus also the first line of
defense of the STL server side.  Requirements:

- Preserve liveness in light of attackers with eavesdrop (read
  incoming packets) and source IP spoof (add outgoing packets)
  capabilities:  Such attackers must not be able to kill existing
  sessions or in-flight handshakes.

- Peer authentication: Use Ed25519 to authenticate client and server
  network metadata.

- Scalability: Minimize per-session server state to support a large
  amount of peers.

- Load shedding/QoS: Avoid dropping high priority packets when
  subjected to packet flood.  (Elliptic curve cryptography at line
  rate might exhaust compute resources)

### 1.3. Encrypted mode requirements

The application layer optionally supports an encrypted mode.
The encrypted mode properties are conservatively chosen to support
a 128-bit level of security comparable to TLS 1.3.
The following features are additionally provided:

- Authenticated encryption: Encrypt application data to conceal
  it from eavesdroppers and protect it against modifications by middle
  boxes.

- Forward secrecy: Construct encryption keys via frequently rotated
  ephemeral keys.

**Non-requirements**

TODO

- Anonymity
- Cryptographic padding
- Features for end users

## 2. Architecture

TODO

### 2.1. Session Object

### 2.2. Unencrypted Mode

### 2.3. Encrypted Mode

## 3. Protocol Specification

### 3.1. Conventions

> TODO: Include a note on keywords such as MUST, MUST NOT, etc.

The protocol assumes that bytes are octets.  Types follow Rust notation.
Scalar types are encoded in little endian order.  Structures of multiple
scalars are laid out byte-aligned packed.

The STL protocol assumes unicast communication between two peers over
the Internet.  The two peers are named "client" and "server".  The
IP address of each peer MUST stay constant.  In the handshake protocol,
the client initiates communication by sending the first packet
A successful handshake may implicitly create application data flows.
Each flow is identified by the tuple (destination UDP port, session ID).
Packets belong to these application data flows MUST only originate
from the client.  The client SHOULD only send these packets to the
server.

Henceforth, we specify cases in which a packet should be dropped.
Unless otherwise noted, peers MUST NOT destroy any other state, such
as the session object, when dropping a packet.

### 3.2. Common Header

All UDP payloads in STL start with the common packet header.
The common packet header is defined as follows.

| Offset | Field          | Type       |
|--------|----------------|------------|
| `0x00` | `version_type` | `u8`       |
| `0x01` | `session_id`   | `[u8; 7]`  |

The `version_type` field contains two packed 4-bit fields:
`version` (high) and `type` (low).

The `version` field is hardcoded to `0x00`.
Incoming packets with any other version number MUST be ignored.

> TODO: Set the version number to `0x01` once v1 is finalized.

The `type` field indicates how to interpret a packet.
It is one of the values in the following table.  Each packet
type is described in detail below.

> TODO: Consider collapsing `version` of `type` into one byte.

Incoming packets with an unsupported `type` MUST be dropped.

| Value  | Protocol    | Meaning              |
|--------|-------------|----------------------|
| `0x01` | Application | Data, Simple Mode    | ~
| `0x02` | Application | Data, Auth Mode      |
| `0x03` | Application | Data, Encrypted Mode | ~
| `0x04` | Application | Data, TLV            |
| `0x81` | Handshake   | Client Initial       |
| `0x82` | Handshake   | Server Continue      |
| `0x83` | Handshake   | Client Accept        |
| `0x84` | Handshake   | Server Accept        |

At offset `0x08` follows packet type-specific data.

## 3.3. Simple Application Protocol

Simple application packets use the following layout.

| Offset | Field          | Type          |
|--------|----------------|---------------|
| `0x00` | `common`       | Common Header |
| `0x08` | `app_data`     | `[u8; ?]`     |

The app data field expands to the end of the UDP payload.
Its length can be derived by subtracting `0x08` from the UDP payload
length.

If any of the following constraints are violated, the packet MUST be
dropped.
- `common.type == 0x01`
- `session_id != 0x00`

The client side logic to process a simple packet is as follows.
- TODO

## 3.4. Encrypted Application Protocol

### 3.4.1 Encrypted Packet

Encrypted application packets use the following layout.

| Offset | Field         | Type       |
|--------|---------------|------------|
| `0x00` | Base Header   |            |
| `0x08` | `mac_tag`     | `[u8; 16]` |
| `0x18` | `seq_compact` | `u32`      |
| `0x1c` | `ciphertext`  | `[u8; ?]`  |

The `ciphertext` and `mac_tag` are outputs of the AEAD cipher
described in Section 3.4.2.  `seq_compact` is the compressed sequence
number described in Section 3.4.3.

### 3.4.2 AEAD Cipher

STL encrypts application packets using the AES-128-GCM AEAD cipher.
(Authenticated encryption with associated data)

At a high-level, AEAD encryption produces a ciphertext and MAC tag
given an encryption key, plaintext to be encrypted, associated data
that is not encrypted, and an initialization vector.

> TODO Document encryption key expansion

### 3.4.3 Sequence Number

Each encrypted application packet is tagged with a sequence number by
the client.  The sequence number is a 64-bit little endian integer.
The sequence number of the first application packet is one.  The
sequence number is incremented by one for every subsequent packet.
In the instance of integer overflow, wraps back around to zero.

The client MUST NOT reuse the same sequence number on two outgoing
packets, even if the message payload is being retransmitted by the
application.

The sequence number is stored in each packet header in unencrypted
compressed form.  The client derives the 32-bit "compact sequence
number" as follows:

  compact_seq := seq & 0xFFFF_FFFF

The server expands the sequence number to its original value.

### 3.4.3 Initialization Vector

It is assumed that the AEAD function is based on a stream cipher
construction.  In STL, a separate AEAD stream is created for every
encrypted application packet.  Stream ciphers such as AES-GCM
or ChaChaPoly require unique a unique value for the initialization
vector to be secure.  Reusing the same key and IV for distinct
streams is considered a "catastrophic failure" because allows it for
trivial recovery of the plaintext.

STL thus takes steps to ensure the IV for each packet is unique.

A new IV MUST be used for every new stream.  The IV size is 12 bytes.
It is laid out as follows.

| Offset | Field          | Type  |
|--------|----------------|-------|
| `0x00` | `udp_dst_port` | `u16` |
| `0x02` | `_pad_02`      | `u16` |
| `0x04` | `seq`          | `u64` |

## 3.5. Handshake Protocol

### 3.5.1. X25519 Key Exchange

TODO

### 3.5.3. Ed25519 Signatures

TODO

### 3.5.4. Handshake Packet

All packets in the handshake protocol use the following layout.

TODO

| Offset | Field         | Type       |
|--------|---------------|------------|
| `0x00` | Base Header   |            |
| `0x08` | `cookie`      | `[u8; 32]` |
| `0x28` | `identity`    | `[u8; 32]` |
| `0x48` | `key_share`   | `[u8; 32]` |
| `0x68` | `random`      | `[u8; 32]` |
| `0x88` | `verify`      | `[u8; 32]` |
| `0xa8` | `suite`       | `u16`      |
| `0xaa` | `next_packet` | `u16`      |

## 5. Design Considerations

### Static Layout

### Session ID size

### Nonce Size

### Unidirectional Mode

### Cryptography

This draft of STL chooses a conservative set of widely deployed
cryptographic algorithms.  These algorithms are thought to have been
subjected to sufficient security research.  High quality open source
implementations are also available.

Recent research h

#### Hash Functions

SHA-256 is extremely widespread and supports hardware acceleration
on x86_64 and armv8.  SHA-256 is vulnerable to length extension
attacks and thus requires the use of the HMAC-SHA256 construction for
key expansion.

It is proposed to use SHAKE-256 instead for all uses of a crypto-
graphic hash function.  (Except Ed25519 signatures, for which it is
unsafe to replace SHA-512)

The handshake cookie has particularly weak security requirements.
If (second-)preimage resistance of the underlying cryptography is
broken, only server-side DDoS mitigation is temporarily degraded.
The handshake mechanism itself remains secure.  The cookie hash
function is also in the "hot path" of a flood attack involving
repeated client initial packets.  The cookie hash function should
thus be chosen for maximum performance.

## 6. Implementation Guidance

### 6.1. Load Shedding

## 7. Related Work

### 7.1. QUIC

QUIC (RFC 9000) offers a superset of the features provided by STL,
which makes it an attractive candidate.

We argue that the QUIC protocol suffers from unsustainable complexity
and inherent inefficiences (TODO write up examples from fd_quic below).

### 7.2. Noise Protocol Framework

TODO
