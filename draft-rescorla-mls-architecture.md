﻿﻿﻿---
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
 -
    ins: A. Kwon
    name: Albert Kwon
    organization: MIT
    email: kwonal@mit.edu
 -
    ins: R. Robert
    name: Raphael Robert
    organization: Wire
    email: raphael@wire.com

normative:
  RFC2119:

--- abstract

This document specifies version 1.0 of the Messaging Layer Security (MLS) protocol.
MLS allows group messaging for a large number of networked clients by providing a delivery service for messages, and potentially an authentication service, in a way that is designed to prevent eavesdropping,
tampering, and message forgery. 

--- middle

# Introduction

End-to-end security is a requirement for instant messaging systems
and is commonly deployed in many such systems. In this context, "end-to-end" captures the notion that 
users of the system enjoy some level of security -- with the precise
level depending on the system design -- even when the messaging
service they are using performs unsatisfactorily.

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
[[TvdM: What precisely do we mean by authentication level here? Also, it's not clear, upon initial reading of this section, what the purpose of this document is. Perhaps we should be more explicit in explain why it's necessary?]]

# General Setting

A Group using a Messaging Service (MS) comprises a set of participants called Members
where each Member is typically expected to own multiple devices, called Clients.
In order to communicate securely, Group Members initially use services at their
disposal to obtain the necessary secrets and credentials required for security.

The Messaging Service (MS) presents as two abstract services that allow
Members to prepare for sending and receiving messages securely :

- An Authentication Service (AS) which is responsible for maintaining
  user long term identities, issuing credentials which allow them to
  authenticate to each other, and potentially distributing
  user signing keys.

- A Delivery Service (DS) which is responsible for receiving and
  redistributing messages between group members.
  In the case of group messaging, the delivery service may also
  be responsible for acting as a "broadcaster" where the sender sends
  a single message to a group which is then forwarded to each
  recipient in the group. The DS is also responsible for storing and
  delivering initial public key material required in order to proceed
  with the group secret key establishment process.
  
  ```
      ----------------      --------------
     | Authentication |    | Delivery     |
     | Service (AS)   |    | Service (DS) |
      ----------------      --------------
                         /        |        \             Group
     *********************************************************
     *                 /          |          \               *
     *                /           |           \              *
     *      ----------       ----------       ----------     *
     *     | Client 0 |     | Client 1 |     | Client N |    *
     *      ----------       ----------       ----------     *
     *      ............................      ...........    *
     *      Member 0                          Member 1       *
     *                                                       *
     *********************************************************
```

In many systems, the AS and the DS are actually operated by the
same entity and may even be the same server. However, they
are logically distinct and, in other systems, may be operated
by different entities, hence we show them as being separate here. Other
partitions are also possible, such as having a separate directory
server.

A typical scenario might look like this:

1. Alice, Bob and Charlie create accounts with a messaging
   service and obtain credentials from the AS.

2. Alice, Bob and Charlie authenticate to the DS and store
   some initial keying material which can be used to send encrypted messages 
   to them for the first time.

3. When Alice wants to send a message to Bob and Charlie, she
   contacts the DS and looks up their initial keying material.
   She uses these keys to establish a new set of keys which she
   can use to send encrypted messages to Bob and Charlie. She then sends the
   encrypted message(s) to the DS, which forwards them to
   the recipients.

4. Bob and/or Charlie respond to Alice's message. Their messages
   might trigger a new key derivation step which allows the shared group
   key to be updated, thus providing post-compromise security.

Clients in groups (and by extension Members) have equal rights
       for managing groups and sending messages, unless specified
       otherwise outside of the messaging protocol, typically at the application layer. Clients may wish to do the following: 

 -  create a group by inviting other members

 -  add one or more members to an existing group

 -  remove one or more members from an existing group

 -  join an existing group

 -  leave a group

 -  send a message to everyone in the group

 -  receive a message from someone in the group

## Group, Members and Clients

In MLS a Group is defined as a set of Members who possibly use multiple
endpoint devices to interact with the Messaging Service.
Only endpoints that are not an AS or a DS are called Clients. These
clients will typically correspond to end-user devices such as phones,
web clients or other devices running MLS.

Each member device owns a long term identity key pair that uniquely defines
its identity to other Members of the Group.
As single end-user may operate multiple devices simultaneously
(e.g., a desktop and a phone) or sequentially (e.g., replacing
one phone with another), hence the formal definition of a Group in MLS
is the set of Clients that has legitimate knowledge of the shared (Encryption)
Group Key established in the group key establishment phase of the protocol.

MLS has been designed to provide similar security guarantees to all Clients,
for all group sizes, even when it reduces to only two Clients.

## Delivery Service

The Delivery Service (DS) is expected to play multiple roles in the
Messaging Service architecture.

Before dispatching the encrypted messages, the DS is first used during
the group shared key establishment phase to provide initial keying material
to a standalone Member trying to establish a new Group.
Depending on the level of trust given by the Group to the Delivery Service,
the functionnal and security guarantees provided by MLS may differ.

### Delivery of the initial keying material

In the MLS group communication establishment process, the first step
exercised by the DS is to store the initial cryptographic key material
provided by every Member. This key material represents the initial contribution
from each member that will be used in the establishment of the shared group
key. Hence this initial keying material MUST be authenticated.

[[BEN] If we keep pushing on having ephemeral signing keys we might
want to store the initial ephemeral signing public key as well as the
initial ephemeral encryption public share. To me it makes more sense to
store it on the DS, so that the AS remains as isolated as possible, which
is probably easier for subsequent security analysis.
]

In an Untrusted setting, it is assumed by the MLS threat model that
the identity provided by the DS to an honest Member of the Group can
be incorrect. Hence, MLS offers the clients a way of verifiying
the relationship between the other members of the group expected
identities and the keys provided by the MS through a public Key
Transparency (KT) log. While this is useful to circumvent trust issues
in the case of a potentially corrupted DS, this check can be
computationnaly costly and privacy leaking for the clients.
[EO It is not clear to me how KT could cause privacy issues? each coporate will be running their own KT server,
and all KT servers will only gossip their signed root head]

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
devices by signaling to the other Clients that one endpoint has
been kicked out of the delivery and MUST be removed from the Group.
This is an absolute requirement to preserve security properties such 
as forward secrecy of messages or post-compromise security.

The policy regarding the time ellapsed before an offline member must
be removed from the group is not specified by this document as it may
vary depending on the security expectations from the Group. Hence it is
left to the application layer to agree upon and signal this value to the
Delivery Service (DS).

## Authentication Service

New Members to the Messaging Service will always need to provide some initial
keying material for other users to potentially use when creating a new Group.
To prevent an attacker to impersonate users, the Authentication Service (AS) will
provide strong authentication mechanism for the Client to use to authenticate
this encryption prekey.

This document does not specify the exact mechanism that allows a Client to obtain
signature keys, the RECOMMANDED design is for a Member to generate an ephemeral
signature keypair for each Client and ask the AS to sign the public keys.
This has the obvious advantage that, in the case of a malicious AS, the attacker
cannot forge an inital encryption public key share on the behalf of the user.
The drawback of that technique is that the AS knows the number of initial public
keys it signed for a specific Member.

In all cases, other Members might want additionnal confidence on the identity associated
with a Client's encryption prekey. In that scenario, it is suggested that the AS
providing long-term identity keys or signing ephemeral signature public keys
publishes the identity of the Member and the public signing key to a Key Transparency
(KT) log for all to see.

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
   active network attacks, replay attacks... Additionally, there is a scenario where a
   compromised DS could potentially leak group membership if it has this
   knowledge (Untrusted and Trusted DS). 

3. Authentication service (AS) compromise: a compromised AS could
   provide incorrect or adversarial identities to clients. As a
   result, a malicious AS could. If there are no mechanisms to verify the
   authenticity of the provided keys (e.g., via out-of-band
   communication between group members or keeping the AS service in
   check using techniques like key transparency), then MLS will only
   provide limited security against a compromised AS.

[[BB.] Relocate this !]
Note that while MLS provides some level of security resilience
against compromised Clients, the maximum security level requires
the endpoints to connect to the messaging service on a regular basis
and to use compliant implementations in order to realize security
operations such as deleting intermediate cryptographic keys.

# System Requirements

As the MLS protocol provides an important service to users, its functional
safety and security are very important parts of the protocol
design. Specifically, MLS is designed to be as resilient as possible against
adversarial interaction and (where possible) Denial of Service (DOS) attacks.

## Functional Requirements

MLS is designed as a large scale group messaging protocol and hence requires to
provide performance and safety to its users.  Messaging systems that implement
MLS must provide support for conversations involving 2 or more participants,
and aim to scale to approximately 50,000 clients, typically including many
Members using multiple devices.

### Asynchronous Usage

No operation in MLS should require two distinct users to be online
simultaneously. In particular, clients participating in conversations protected
using MLS must be able to update shared keys, add or remove new members, and
send messages and attachments without waiting for another user's reply.

Messaging systems that implement MLS must provide a transport layer for
delivering messages asynchronously. This transport layer must also support
delivery ACKs and NACKs and a mechanism for retrying message delivery.

### Recovery After State Loss

Conversation participants whose local MLS state is lost or corrupted
must be able to reinitialize their state and continue participating
in the conversation. This requires to keep track of the group key that
must be used to decrypt the next message. Loss of the current group
key may force the user to recompute it for the latest message and
hence lose messages encrypted with keys in-between the old and
the new group keys.

### Support for Multiple Devices

It is typically expected for Members of the Group to own different devices.

A new device can join the group and will be considered as a new Client by
the protocol. Hence this Client will not gain access to the history even if
it is owned by someone who is already a Member of the Group.
Restoring history is typically not allowed at the protocol level but can still
be achieved at the application layer by an out-of-band process provided
by the owner of the Authentication Service.

### Extensibility / Pluggability

Messages that don't affect the group state can carry arbitrary payload with
the purpose of sharing that payload between group members. No assumptions
are made about the format of the payload.

### Privacy

The protocol is designed in a way that limits the server-side (AS and DS)
metadata footprint. The DS must only persist data required for the delivery
of messages and avoid Personally Identifiable Information (PII) or other
sensitive metadata wherever possible. A Messaging Service provider that has
control over both the AS and the DS, will not be able to correllate encrypted
messages forwarded by the DS, with the initial public keypairs signed by the AS
when the Clients use ephemeral signature keys.

### Federation

The protocol aims to be compatible with federated environments. While this
document does not specify all necessary mechanisms required for federation,
it allows for more than one AS/DS to exist.

### Compatibility with future versions of MLS

One of the main requirements of the protocol is to make sure that if multiple
versions of MLS coexist in the future, the protocol provides a strong and
unambiguous version negotiation mechanism. This mechanism prevents from
version downgrade attacks where an attacker would actively rewrite handshake
messages with a lower protocol version than the ones originally offered by
the endpoints. When multiple versions of MLS are available, the negotiation
protocol guarantees that the version agreed upon will be the highest version
supported in commun by the group. As no other version exist at the moment,
this document does not do any recommandation on alternative techniques such
as using different versions of MLS for different subgroups.

## Security Requirements

[[TODO: should these be stated as assertions ("MLS guarantees that...") or
goals ("MLS aims to guarantee that...")?]]

### Connections between Clients and Servers (one-to-one)

In the case where clients need to connect to an AS or a DS to obtain specific
informations that are not availaible. Clients MUST use the Transport Layer
Security (TLS) protocol version 1.3 or higher. Clients MUST NOT use any legacy
versions of TLS.

[[BB.] I am assuming TLS here but maybe something else can be done]


### Message Secrecy and Authentication

The trust establishment step of the MLS protocol is followed by a
conversation protection step where encryption is used by clients to
transmit authenticated messages to other clients through the DS.
This ensures that the DS doesn't have access to this Group-private content.

MLS aims to provide Secrecy, Integrity and Authentication for all messages.

Message Secrecy in the context of MLS means that only intended recipients
(current group members), should be able to read any message sent to the group,
even in the context of an active adversary as described in the threat model.

Message Integrity and Authentication mean that an honest client should only
accept a message if it was sent by a group member.

A corollary to that statement is that AS
and DS can't read the content of messages sent between Members as
they are not Members of the Group. It is expected from MLS to
optionnally provide additional protections regarding traffic analysis
techniques to reduce the ability of adversaries or a compromised
member of the messaging system to deduce the content of the messages
depending on (for example) their size. One of these protection is
typically padding messages in order to produce ciphertexts of standard
length. While this protection is highly recommended it is not
mandatory as it can be costly in terms of performance for clients
and the MS.

#### Forward and Post-Compromise Security

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

PCS ensures that if a group member is compromised at some time t but
subsequently performs an update at some time t', then all MLS guarantees should
apply to messages sent after time t'. For example, if an adversary learns all
secrets known to Alice at time t, including both Alice's secret keys and all
shared group keys, but then Alice performs a key update at time t', then the
adversary should be unable to violate any of the MLS security properties after
time t'.

Both of these properties must be satisfied even against compromised
DS and AS.

#### Membership Changes

MLS aims to provide agreement on group membership. That is, all
group Members have agreed on the list of current group members.

Some applications may wish to enforce ACLs to limit addition or removal
of group members, to privileged users. Others may wish to require
authorisation from the current group members or a subset of it.
Regardless, MLS does not allow addition or removal of group members
without informing all other members.

Once a Member is part of a group, the set of devices controlled by the
member should only be altered by an authorized member of the group.
This authorization could depend on the application: some applications
might want to allow certain other members of the group to add or
remove devices on behalf of another member, while other applications
might want a more strict policy and allow only the owner of the
devices to add or remove them at the potential cost of weaker PCS guarantees.

Members who are removed from a group do not enjoy special privileges:
compromise of a removed group member will not affect the security
of messages sent after their removal.

[TODO: do we want to hide the number of devices per user in MLS?  it's
listed as P2 in the spreadsheet, but is somewhat related to this
property and membership changes.]

#### Security of Attachments

The security properties expected for attachments in the MLS protocol are
very similar to the ones expected from messages. The distinction between
messages and attachments stems from the fact that the typical average time
between the download of a message and the one from the attachements
may be different. For many reasons, the usual one being the lack of
high bandwith network connectivity, the lifetime of the cryptographic
keys for attachments is usually higher than for messages, hence slightly
weakening the PCS guarantees for attachments.

# Security Considerations

Security considerations are discussed throughout this document but in
particular in the Security Requirements section.

--- back





