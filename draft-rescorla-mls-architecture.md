---
title: Messaging Layer Security Architecture
abbrev: MLS Architecture
docname: draft-rescorla-mls-architecture-latest
category: info

ipr: trust200902
area: Security
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: E. Rescorla
    name: Eric Rescorla
    organization: Mozilla
    email: ekr@rtfm.com
 -
    ins: B. Beurdouche
    name: Benjamin Beurdouche
    organization: INRIA
    email: benjamin.beurdouche@inria.fr
 -
    ins: E. Omara
    name: Emad Omara
    organization: Google
    email: emadomara@google.com
 -
    ins: S. Inguva
    name: Srinivas Inguva
    organization: Twitter
    email: singuva@twitter.com

normative:
  RFC2119:

--- abstract

TODO

--- middle

# Introduction

End-to-end security is a requirement for instant messaging systems
and is commonly deployed in many such systems designed over the past
few years. In this context, what end-to-end means is that the
users of the system enjoy some level of security -- with the precise
level depending on the system design -- even when the messaging
service they are using misbehaves.

Messaging Layer Security (MLS) specifies an architecture (this document)
and an abstract protocol [TODO:XREF] for providing end-to-end security
in this setting. MLS is not intended as a full instant messaging
protocol but rather is intended to be embedded in a concrete protocol
such as XMPP [TODO:REF]. In addition, it does not specify a complete
wire encoding, but rather a set of abstract data structures which
can then be mapped onto a variety of concrete encodings, such as
TLS {{?I-D.ietf-tls-tls13}}, CBOR {{?RFC7049}}, and JSON {{?RFC7159}}.
Implementations which adopt compatible encodings should be able to
have some degree of interoperability at the message level (though perhaps
not at the authentication level).


# General Setting

[TODO: Need some ASCII art]

A model system is shown in [TODO: Figure].

The messaging service presents as two abstract services:

- An Authentication Server (AS) which is responsible for maintaining
  user identities, issuing credentials which allow them to
  authenticate to each other, and potentially distributing
  user keying material.

- A Message Switch (MS) which is responsible for delivering messages
  between users. In the case of group messaging, the message
  switch may also be responsible for acting as an "exploder"
  where the sender sends a single message to a group and
  the switch then forwards it to each recipient.

In many systems, the AS and the MS are actually operated by the
same entity and may even be the same server. However, they
are logically distinct and, in other systems, may be operated
by different entities so we show them as separate here. Other
partitions are also possible, such as having a separate directory
server.

A typical scenario might look something like this:

1. Alice, Bob, and Charlie create accounts with the messaging
   service and obtain credentials from the AS.

1. Alice, Bob, and Charlie authenticate to the MS and store
   some keying material which can be used to encrypt to them
   for the first time.

1. When Alice wants to send a message to Bob and Charlie, she
   contacts the MS and looks up their keying material. She
   uses those keys to establish a set of keys which she can
   use to send to Bob and Charlie. She then sends the
   encrypted message(s) to the MS, which forwards them to
   the ultimate recipients.

1. Bob and/or Charlie respond to Alice's message. Their messages
   might include new keys which allow the joint keys to be updated,
   thus providing post-compromise security {{post-compromise-secrecy}}.

## Clients

Endpoints that are not an AS nor a MS are called Clients. These
clients will typically correspond to end-user devices such as phones,
web clients or other devices running MLS.

Each client owns a set of keys that uniquely define the identity of
this endpoint. Multiple clients can be federated under the identity of
a single Member of the Group. This is often the case as a Member,
typically an individual, will often use multiple devices to interact
with the messaging service.

MLS has been designed to provide similar security guarantees to all
clients. Note that while MLS provide some level of security resilience
against of a compromised clients, the maximum security level requires
the endpoints to connect to the messaging service on a regular basis
and to use compliant implementations in order to realize security
operations such as deleting intermediate cryptographic keys.
Additionally, MLS fundamentally relies on the fact that clients are
not malicious and do not actively collaborate with the adversary by
leaking cryptographic keys or application data content.

## Messaging Server

## Authentication Service


# Threat Model


# System Requirements

## Functional Requirements

### Asynchronous Delivery

Messaging systems that implement MLS must provide a transport
layer for delivering messages asynchronously.

This transport layer must also support delivery ACKs and NACKs
and a mechanism for retrying message delivery.

### Asynchronous Key Update

Clients participating in conversations protected using MLS must
be able to update shared keys asynchronously.

### Recovery After State Loss

Conversation participants whose local MLS state is lost or corrupted
must be able to reinitialize their state and continue participating
in the conversation.

## Message Protection

### Message Secrecy

### Message Authentication

### Security of Attachments

## Support for Group Messaging

Messaging systems that implement MLS must provide support for
conversations involving 2 or more participants.

### Secrecy After Member Exit

Message secrecy properties must be preserved after any participant
exits the conversation.

## Support for Multiple Devices

### Adding New Devices

## System Resilience

### Forward Secrecy

###  Post-Compromise Secrecy

### Offline/old Devices

## Protection Against Server Misbehavior

### Deterministic Group Membership

### Servers and Post-Compromise Secrecy

### Unauthorized Device Additions


# Security Considerations

TODO

--- back
