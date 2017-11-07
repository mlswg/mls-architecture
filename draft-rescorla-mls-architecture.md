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
are logically distinct, and in other systems may be operated
by different entities so we show them as separate here.







## Clients

## Messaging Server

## Authentication Service

# Threat Model



# System Requirements

## Functional Requirements

### Asynchronous Delivery

### Asynchronous Key Update

### Recovery After State Loss

## Message Protection

### Message Secrecy

### Message Authentication

### Security of Attachments

## Support for Group Messaging

### Secrecy After Member Exit

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
