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
have some degree of interoperability at the message level, though
they may have incompatible identity/authentication infrastructures.

This document is intended to describe the overall messaging
system architecture which the MLS protocol fits into, and the
requirements which it is intended to fulfill.


# General Setting

A Group using a Messaging Service (MS) comprises a set of participants
called Members where each Member is typically expected to own multiple
devices, called Clients.  In order to communicate securely, Group
Members initially use services at their disposal to obtain the
necessary secrets and credentials required for security.

The Messaging Service (MS) presents as two abstract services that allow
Members to prepare for sending and receiving messages securely:

- An Authentication Service (AS) which is responsible for maintaining
  user long term identities, issuing credentials which allow them to
  authenticate each other, and potentially allowing users to
  discover each others long-term identity keys.

- A Delivery Service (DS) which is responsible for receiving and
  redistributing messages between group members.
  In the case of group messaging, the delivery service may also
  be responsible for acting as a "broadcaster" where the sender sends
  a single message to a group which is then forwarded to each
  recipient in the group. The DS is also responsible for storing and
  delivering initial public key material required in order to proceed
  with the group secret key establishment process.

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

In many systems, the AS and the DS are actually operated by the
same entity and may even be the same server. However, they
are logically distinct and, in other systems, may be operated
by different entities, hence we show them as being separate here. Other
partitions are also possible, such as having a separate directory
server.

[[TODO: Should we actually break this into three services, with the
directory being a separate service.]]

A typical group messaging scenario might look like this:

1. Alice, Bob and Charlie create accounts with a messaging
   service and obtain credentials from the AS.

2. Alice, Bob and Charlie authenticate to the DS and store
   some initial keying material which can be used to send encrypted messages
   to them for the first time. This keying material is authenticated
   with their long term credentials.

3. When Alice wants to send a message to Bob and Charlie, she
   contacts the DS and looks up their initial keying material.
   She uses these keys to establish a new set of keys which she
   can use to send encrypted messages to Bob and Charlie. She then sends the
   encrypted message(s) to the DS, which forwards them to
   the recipients.

4. Bob and/or Charlie respond to Alice's message. Their messages
   might trigger a new key derivation step which allows the shared group
   key to be updated to provide post-compromise security {{fs-and-pcs}}.

Clients may wish to do the following:

 -  create a group by inviting a set of other members;

 -  add one or more members to an existing group;

 -  remove one or more members from an existing group;

 -  join an existing group;

 -  leave a group;

 -  send a message to everyone in the group;

 -  receive a message from someone in the group.

At the cryptographic level, Clients in groups (and by extension Members)
are peers. For instance, any Client should be able to add a member
to a group. This is in contrast so some designs in which there
is a single group controller who can modify the group. MLS is
compatible with having group administration restricted to
certain users, but we assume that those restrictions are enforced
by authentication and access control. Thus, for instance, while
it might be technically possible for any member to send a message
adding a new member to a group, the group might have the policy
that only certain members are allowed to make changes and thus
other members just ignore such a message from an unauthorized
user.



## Group, Members and Clients

In MLS a Group is defined as a set of Members who possibly use multiple
endpoint devices to interact with the Messaging Service.
Only endpoints that are not an AS or a DS are called Clients. These
clients will typically correspond to end-user devices such as phones,
web clients or other devices running MLS.

Each member device owns a long term identity key pair that uniquely defines
its identity to other Members of the Group.
[[TODO: Probably we can rewrite all occurrences
of "member device" to "Client", or leave all-but-one to indicate the
relation.]]
Because a single Member may operate multiple devices simultaneously
(e.g., a desktop and a phone) or sequentially (e.g., replacing
one phone with another), the formal definition of a Group in MLS
is the set of Clients that has legitimate knowledge of the shared (Encryption)
Group Key established in the group key establishment phase of the protocol.

In some messaging systems, Clients belonging to the same Member must
all share the same identity key pair, but MLS does not assume this.
The MLS architecture considers the more general case and allows for
important use cases, such as a Member adding a new Client when all their
existing clients are offline. For systems that allow multiple identity
key pairs per Member, some mechanism is required to detect the addition
of new, bogus Clients.  Key Transparency [TODO:REF] is one such
potential mechanism, but others are also possible.

MLS has been designed to provide similar security guarantees to all Clients,
for all group sizes, even when it reduces to only two Clients.

## Authentication Service

The basic function of the Authentication Service is to provide a
trusted mapping from user identities (usernames, phone numbers, etc.)
to identity keys. An identity service can be implemented in a variety
of ways, but the two most natural ones are:
[[TODO: must clarify how user "identity" relates to
"Member" and "Client".]]

* A certificate authority which signs some sort of portable credential
  binding an identity to a key.

* A directory server which provides the key for a given identity
  (presumably this connection is secured via some form of transport
  security such as TLS).

By definition, the AS is invested with a large amount of trust.
A malicious AS can impersonate -- or allow an attacker to impersonate --
any user of the system. This risk can be mitigated by publishing
the binding between identities and keys in a public log such
as Key Transparency (KT) [REF]. It is possible to build a functional
MLS system without any kind of public key logging, but such a system will
necessarily be somewhat vulnerable to attack by a malicious or untrusted AS.


## Delivery Service

The Delivery Service (DS) is expected to play multiple roles in the
Messaging Service architecture:

* To act as a directory service providing the keying material
  (authentication keys and initial keying material) to sending
  Clients. This allows a Client to establish a shared key
  and send encrypted messages to other Clients even if the
  other Client is offline.

* To route messages between Clients.


Depending on the level of trust given by the Group to the Delivery Service,
the functional and security guarantees provided by MLS may differ.

### Key Storage

Upon joining the system, each Client stores its initial cryptographic
key material with the DS. This key material represents the initial contribution
from each member that will be used in the establishment of the shared group
key. Hence this initial keying material MUST be authenticated using
the Client's identity key. Thus, the Client stores:

* A credential from the Authentication service attesting to the
  binding between the Member and the Client's identity key.
* The member's initial keying material signed with the Client's
  identity key.

As noted above, Members may have multiple Clients, each with their
own keying material, and thus there may be multiple entries stored
by each Member.

### Key Retrieval

When a Client wishes to establish a group and send an initial message
to that group, it contacts the DS and retrieves the initial key 
material for each other Member, verifies it using the identity key,
and then is able to form a joint key with each other Client, and
from those forms the group key, which it can use for the encryption of 
messages.


### Delivery of messages and attachments {#delivery-guarantees}

The DS's main responsibility is to ensure delivery of messages.
Specifically, we assume that DSs provide:

* Reliable delivery -- when a message is provided to the DS,
  it is eventually delivered to all group members.

* In-order delivery -- messages are delivered to the group
  in the order they are received from a given Client
  and in approximately the order which they are sent
  by Clients. The latter is an approximate guarantee because
  multiple Clients may send messages at the same time
  and so the DS needs some latitude in reordering between Clients.

* Consistent ordering -- the DS must ensure that all Clients
  have the same view of message ordering.

Note that the DS may provide ordering guarantees by ensuring
in-order delivery or by providing messages with some kind
of sequence information and allowing clients to reorder on
receipt.

The MLS protocol itself should be able to verify these properties.
For instance, if the DS reorders messages from a Client or provides
different Clients with inconsistent orderings, then Clients
should be able to detect this misconduct. However, MLS need
not provide mechanisms to recover from a misbehaving DS.

Note that some forms of DS misbehavior are still possible and
difficult to detect. For instance, a DS can simply refuse
to relay messages to and from a given Client. Without some
sort of side information, other Clients cannot generally
distinguish this form of Denial of Service (DoS) attack
from the Client being actually offline.

### Membership knowledge

[[TODO(ekr@rtfm.com): This needs to be softened quite a bit. In general, the DS
is going to have real-time information about who is in each
group if you are doing server-side fanout.]]

A particularly important security constraint in that an adversary
must not be able to gain access to information about the identity of
group members and the number of clients.

To prevent that from happening, the MLS threat model {{threat-model}}
considers the case of a corrupted or untrusted DS that would leak all
information at its disposal. Hence, in this Untrusted DS scenario, MLS
will enforce that the DS MUST NOT be aware these informations. While not
providing the DS with this information might be enough in certain
scenarios, the strong threat model of MLS in this scenario provides
counter measures against potential traffic analysis that could be done
at the DS level.

### Membership and offline members

[[TODO(ekr@rtfm.com): Rewrite this a bit to be clearer]]

Clients that have been offline for a long time or not performing
mandatory security operations will affect the security of the
group in different ways depending on the amount of trust given to the DS.

In the scenario where the DS is Trusted, the MLS design ensures that
the protocol provides security against permanently offline members or
devices by signaling to the other Clients that one endpoint has
been kicked out of the delivery and MUST be removed from the Group.
This is an absolute requirement to preserve security properties such
as forward secrecy of messages or post-compromise security.

The policy regarding the time elapsed before an offline member must
be removed from the group is not specified by this document as it may
vary depending on the security expectations from the Group. Hence it is
left to the application layer to agree upon and signal this value to the
Delivery Service (DS).


# Threat Model {#threat-model}

In order to mitigate several categories of attacks across parts of
the MLS architecture, we assume the attacker to be an active network
attacker. This means an adversary which has complete control over the
network used to communicate between the parties [RFC3552].
This assumption remains valid for communications across multiple
authentication or delivery servers if these have to collaborate
to provide a client with some kind of information.


### Delivery Service Compromise

MLS is intended to provide strong guarantees in the face of compromise
of the DS. Even a totally compromised DS should not be able to read
messages or inject messages that will be acceptable to legitimate
Clients. It should also not be able to undetectably remove, reorder
or replay messages.

However, a DS can mount a variety of DoS attacks on the system,
including total DoS attacks (where it simply refuses to forward any
messages) and partial DoS attacks (where it refuses to forward
messages to and from specific Clients). As noted in
{{delivery-guarantees}}, these attacks are only partially detectable
by clients. Ultimately, failure of the DS to provide reasonable
service must be dealt with as a customer service matter, not via
technology.

Because the DS is responsible for providing the initial keying
material to Clients, it can provide stale keys. This doesn't
inherently lead to compromise of the message stream, but does
allow it to attack forward security to a limited extent.
This threat can be mitigated by having initial keys expire.


### Authentication Service Compromise

A compromised AS is a serious matter, as the AS can provide
incorrect or adversarial identities to clients.  As noted in
{{authentication-service}}, mitigating this form of attack requires
some sort of transparency/logging mechanism.  Without such a mechanism,
MLS will only provide limited security against a compromised AS.



### Client Service Compromise

In general, MLS only provides limited protection against compromised
Clients. When the Client is compromised, then the attacker will
obviously be able to decrypt any messages for groups in which the
Client is a member. It will also be able to send messages
impersonating the compromised Client.
[[TODO: The above would be clearer with a
restriction along the lines of "until the honest Client performs another
exchange" or something similar.]]

MLS attempts to provide some security in the face of client
compromise. Specifically:

* MLS provides Forward security and Post-compromise security {{fs-and-pcs}}.
* Clients should not be able to send messages to groups.
  which appear to be from other Clients {{message-secrecy-authentication}}.
* Clients should not be able to perform trivial denial of service attacks {{denial-of-service}}.

# System Requirements

As the MLS protocol provides an important service to users, its functional
safety and security are very important parts of the protocol
design. Specifically, MLS is designed to be as resilient as possible against
adversarial interaction and (where possible) Denial of Service (DoS) attacks.

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
delivering messages asynchronously and reliably.

### Recovery After State Loss

Conversation participants whose local MLS state is lost or corrupted
must be able to reinitialize their state and continue participating
in the conversation. This may entail some level of message loss, but
should not result in permanent exclusion from the group.


### Support for Multiple Devices

It is typically expected for Members of the Group to own different devices.

A new device can join the group and will be considered as a new Client by
the protocol. Hence this Client will not gain access to the history even if
it is owned by someone who is already a Member of the Group.
Restoring history is typically not allowed at the protocol level but applications
may elect to provide such a mechanism outside of MLS.
[[TODO: Perhaps relate the above to identity?]]

### Extensibility / Pluggability

Messages that don't affect the group state can carry arbitrary payload with
the purpose of sharing that payload between group members. No assumptions
are made about the format of the payload.

### Privacy

The protocol is designed in a way that limits the server-side (AS and DS)
metadata footprint. The DS must only persist data required for the delivery
of messages and avoid Personally Identifiable Information (PII) or other
sensitive metadata wherever possible. A Messaging Service provider that has
control over both the AS and the DS, will not be able to correlate encrypted
messages forwarded by the DS, with the initial public keypairs signed by the AS.


### Federation

The protocol aims to be compatible with federated environments. While this
document does not specify all necessary mechanisms required for federation,
it allows for more than one AS/DS to exist.

### Compatibility with future versions of MLS

One of the main requirements of the protocol is to make sure that if multiple
versions of MLS coexist in the future, the protocol provides a strong and
unambiguous version negotiation mechanism. This mechanism must prevent
version downgrade attacks where an attacker would actively rewrite handshake
messages with a lower protocol version than the ones originally offered by
the endpoints. When multiple versions of MLS are available, the negotiation
protocol must guarantees that the version agreed upon will be the highest version
supported in common by the group.

## Security Requirements

[[TODO: should these be stated as assertions ("MLS guarantees that...") or
goals ("MLS aims to guarantee that...")?]]

### Connections between Clients and Servers (one-to-one)

We assume that all transport connections are secured via some transport
layer security mechanism such as TLS.

### Message Secrecy and Authentication {#message-secrecy-authentication}

The trust establishment step of the MLS protocol is followed by a
conversation protection step where encryption is used by clients to
transmit authenticated messages to other clients through the DS.
This ensures that the DS doesn't have access to this Group-private content.

MLS aims to provide Secrecy, Integrity and Authentication for all messages.

Message Secrecy in the context of MLS means that only intended recipients
(current group members), should be able to read any message sent to the group,
even in the context of an active adversary as described in the threat model.

Message Integrity and Authentication mean that an honest Client should only
accept a message if it was sent by a group member and that one Client
must not be able to send a message which other Clients accept
as being from another Client.

A corollary to that statement is that AS
and DS can't read the content of messages sent between Members as
they are not Members of the Group. It is expected from MLS to
optionally provide additional protections regarding traffic analysis
techniques to reduce the ability of adversaries or a compromised
member of the messaging system to deduce the content of the messages
depending on (for example) their size. One of these protection is
typically padding messages in order to produce ciphertexts of standard
length. While this protection is highly recommended it is not
mandatory as it can be costly in terms of performance for clients
and the MS.

Message content can be deniable if the signature keys are exchanged over a deniable channel prior to signing messages.

#### Forward and Post-Compromise Security {#fs-and-pcs}

MLS provides additional protection regarding secrecy of past messages
and future messages. These cryptographic security properties are
Perfect Forward Secrecy (PFS) and Post-Compromise Security (PCS).

PFS ensures that access to all encrypted traffic history combined
with an access to all current keying material on clients will not
defeat the secrecy properties of messages older than the oldest key of
the client.
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
group members have agreed on the list of current group members.

Some applications may wish to enforce ACLs to limit addition or removal
of group members, to privileged users. Others may wish to require
authorisation from the current group members or a subset of it.
Regardless, MLS does not allow addition or removal of group members
without informing all other members.

Once a Member is part of a Group, the set of devices controlled by the
member should only be altered by an authorized member of the group.
This authorization could depend on the application: some applications
might want to allow certain other members of the group to add or
remove devices on behalf of another member, while other applications
might want a more strict policy and allow only the owner of the
devices to add or remove them at the potential cost of weaker PCS guarantees.

Members who are removed from a group do not enjoy special privileges:
compromise of a removed group member will not affect the security
of messages sent after their removal.

#### Security of Attachments

The security properties expected for attachments in the MLS protocol are
very similar to the ones expected from messages. The distinction between
messages and attachments stems from the fact that the typical average time
between the download of a message and the one from the attachments
may be different. For many reasons, the usual one being the lack of
high bandwidth network connectivity, the lifetime of the cryptographic
keys for attachments is usually higher than for messages, hence slightly
weakening the PCS guarantees for attachments.

#### Denial of Service {#denial-of-service}

In general we do not consider denial of service to be the responsibility of the protocol. However,
it should not be possible for anyone to perform a trivial denial of service from which it is hard to
recover.

---- back
