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

The trust establishment step of the MLS protocol is followed by a
conversation protection step where encryption may be used by clients to
transmit authenticated information to other clients through the MS,
making sure that the MS doesn't have access to this Group-private content.
MLS provide security properties such as message secrecy, integrity
and authentication additionnally to repudiability and unlinkability
(see below).

### Message Secrecy

Message Secrecy in the context of MLS means that only intended
recipients, currently valid members of the group, should be able to
read the message. A corollary to that statement is that AS
and MS can't read the content of the content of messages send
between Members are they are not part of the Group. It is expected
from MLS to provide additional protections regarding traffic analysis
techniques to reduce the ability of adversaries or a compromised
member of the messaging system to deduce the content of the messages
depending on (for example) their size. One of these protection is
typically padding messages in order to produce ciphertext of standard
length. While this protection is highly recommended it is not
mandatory as it can be costly in terms of performance for clients
and the MS.

MLS provides additional protection regarding secrecy of past messages
and future messages. These cryptographic security properties are
Perfect Forward Secrecy (PFS) and Post-Compromise Security (PCS).
PFS ensures that access to all encrypted traffic history combined
with an access to all current keying material on clients will not
defeat the secrecy properties of messages older than the oldest key.
Note that this means that clients have the extremely important role
of deleting appropriate keys as soon as they have been used with
the expected message, otherwise the secrecy of the messages and the
security for MLS is considerably weakened.

### Message Authentication and Integrity

Message Integrity and Authentication are properties enforced by MLS.
When the protocol is under attack, it is typically expected by the threat
model that messages will be altered, dropped or substituted by the
adversary. MLS guarantees that under these circumstances an honest
client will not accept one of these scenarios and will reject messages
modified in transit or that have not by successfully authenticated as
a message from the correct Member.

In messaging systems, authentication is a very important part of the
design especially in strong adversarial environnements. This requires
MLS to provide message repudiability and unlinkability properties.
These guarantee that only Members of the group are able to verify
that a message has been sent by a specific Member but will not allow
an external entity having access to all history and keys to link a
message to a specific client, or by extension Member, (Repudiability)
and doesn't allow an external entity to link a specific Member to a
set of specific messages in the conversation (Unlinkability).
(Note that MLS is specifically careful about the case where a Member
of the group is leaking the messages and keys in that scenario.)


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
