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

## Clients

## Messaging Server

## Authentication Service

# Threat Model

# System Requirements

## Functional Requirements

### Asynchronous Delivery

Messaging systems that implement MLS must provide a transport layer for delivering messages asynchronously.

This transport layer must also support delivery ACKs and NACKs and a mechanism for retrying message delivery.

### Asynchronous Key Update

Clients participating in conversations protected using MLS must be able to update shared keys asynchronously.

### Recovery After State Loss

Conversation participants whose local MLS state is lost or corrupted must be able to reinitialize their state and continue participating in the conversation.

## Message Protection

### Message Secrecy

### Message Authentication

### Security of Attachments

## Support for Group Messaging

Messaging systems that implement MLS must provide support for conversations involving 2 or more participants.

### Secrecy After Member Exit

Message secrecy properties must be preserved after any participant exits the conversation.

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
