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
few years. TODO


# General Setting

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
