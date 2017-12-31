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

## Delivery Service

The Delivery Service (DS) is expected to play multiple roles in the
MLS architecture.

Multiple levels of security and trust for the DS are considered by MLS
according to each tasks performed by the DS.

### Delivery of the initial keying material

In the MLS group communication establishment process, the first step
exercised by the DS is to store the initial cryptographic key material
provided by every Member. This key material represents the initial public
identity of the Member and will subsequently be used to establish
the set of keys that will be used by the Members to communicate with
other members of the group.

In an Untrusted setting, it is assumed by the MLS threat model that
the identity provided by the DS to an honest Member of the Group can
be incorrect. Hence, MLS offers the clients a way of multilaterally
verify the relationship between the other members of the group expected
identities and the keys provided by the MS through a public Key
Transparency (KT) log. While this is useful to circumvent trust issues
in the case of a potentially corrupted DS, this check can be
computationnaly costly for the clients.

In a Trusted setting, the DS is expected to always provide the correct
and most up-to-date information to a Member requiring another Member's
initial keying material. Still, clients can choose to examine the KT log,
if available, to make sure the keys they will be using are correct.

### Delivery of messages and attachments

Delivery in order and resilience against intermittent message loss
are the two main properties expected by MLS from the DS.
Another guarantee provided by MLS is that Clients will know after
receiving a message by a Member that all previous message sent by
this member have been properly received.

Additionally the DS is expected to be able, depending on the expectations
of the Group, to send acknowledgments (ACKs or NACKs) and to exercise
retries when a message has not been delivered properly to a client.
Meanwhile, it is possible for multiple reasons that messages can be
indefinitely hold by an dishonest or malfunctionning DS, a network loss, etc.
In this Denial Of Service scenario, the receiver has no knowledge
of this situation until it tries sending a message to the Group
and receives no valid acknowledgment.

It is typically expected that servers that are not trusted regarding
correct delivery will not be trusted regarding the group membership
information either.

### Membership knowledge

A particularly important security constraint in that an adversary
must not be able to gain access to information about the identity of
group members and the number of clients.

To prevent that from happening, the MLS threat model considers the case
of a corrupted or untrusted DS that would leak all information at its
disposal. Hence, in this Untrusted DS scenario, MLS will enforce that
the DS MUST NOT be aware these informations. While not providing the
DS with this information might be enough in certain scenarios, the
strong threat model of MLS in this scenario provides counter measures
against potential traffic analysis that could be done at the DS level.

### Membership and offline members

Clients that have been offline for a long time or not performing
mandatory security operations will affect the security of the
group in different ways depending on the amount of trust given to the DS.

In the scenario where the DS is Trusted, the MLS design ensures that
the protocol provides security against permanently offline members or
devices by signaling to the Members of the Group that one endpoint has
been kicked out of the delivery. This is an absolute requirement to
preserve security properties such as forward secrecy of messages or
post-compromise security.

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
