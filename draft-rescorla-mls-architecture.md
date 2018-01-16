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

In order to mitigate several categories of attacks across parts of
the MLS architecture, we assume the attacker to be an active network
attacker. This means an adversary which has complete control over the
network used to communicate between the parties [RFC3552].
This assumption remains valid for communications across multiple
authentication or delivery servers if these have to collaborate
to provide a client with some kind of information.

Additionally, the MLS threat model considers possible compromissions
of both Clients and the Authentication (AS) or Delivery (DS) services. In these case
the protocol provide resilience against multiple scenarios described
in the following sections. Typically, the Delivery Service (DS) will not
be able to inject messages in the group conversation or compromise
the identity of the group members.
Depending on the level of trust given by the group to the DS, the
MLS protocol will provide the group, the AS and the DS with specific
sets of security properties. Different scenarios are considered in this
architecture document and are described in subsequent sections of this
document:

1. Client compromise: the client actively forwards secret keys, messages,
   group membership or metadata to the adversary (this dishonest client
   scenario is the only case able to defeat completely the security
   properties provided by MLS). Specific client keys, long term key or
   messages might be compromised, in this scenarios MLS will provide
   limited security.

2. Delivery Service (DS) compromise: the initial keying material delivery
   can provide wrong or adversarial keys the client (Untrusted DS).
   The DS can provide previously correct initial keys that may not be
   up to date anymore when multiple DS are involved (Trusted DS).
   Reliability of in-order delivery or message delivery all-together
   might be compromised for multiple reasons such as networking failure,
   active network attacks... Additionally, there is a scenario where a
   compromised DS could potentially leak group membership if it has this
   knowledge (Untrusted and Trusted DS).

3. Authentication service (AS) compromise: a compromised AS could
   provide incorrect or adversarial identities to clients.
   [TODO: Expand on compromised authentication service]


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
