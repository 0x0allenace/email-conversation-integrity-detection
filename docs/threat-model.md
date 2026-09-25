# Threat Model

## 1. Purpose

This document defines the threats that Email Clone Detector is intended to identify and the assumptions made by the detection system.

The primary focus is email-based impersonation and Business Email Compromise involving established business conversations.

---

## 2. Security Objective

**Primary objective:**

> Detect email messages that appear to originate from an established participant but contain evidence suggesting impersonation, conversation hijacking, or abnormal communication behavior.

**Secondary objectives include:**

- Provide explainable evidence
- Reduce time to detection
- Assist SOC investigations
- Generate structured detection events
- Support SIEM integration

---

## 3. Threat Actors

The system considers several attacker profiles.

### 3.1 External Impersonator

An attacker who does not control a legitimate participant's mailbox.

Potential techniques:

- Lookalike domain
- Display-name spoofing
- Reply-To manipulation
- Thread cloning
- Phishing

### 3.2 Compromised Account Attacker

An attacker who has obtained access to a legitimate mailbox.

Potential behavior:

- Conversation hijacking
- Credential abuse
- Financial fraud
- Malicious links
- Malicious attachments
- Recipient manipulation

This scenario is more difficult because the attacker may use a legitimate sender identity.

### 3.3 Infrastructure Impersonator

An attacker who attempts to reproduce legitimate email infrastructure or use infrastructure that appears trustworthy.

Potential indicators:

- Similar domains
- Similar hostnames
- New mail servers
- Unexpected IP addresses
- Unexpected sending infrastructure

---

## 4. Assets

Potentially protected assets include:

- Business email conversations
- Employee identities
- Customer communications
- Supplier communications
- Financial information
- Contracts
- Invoices
- Credentials
- Internal business information
- Attachments

---

## 5. Trust Boundaries

```text
                 Internet
                    │
                    ▼
             External Sender
                    │
                    ▼
             Email Gateway
                    │
                    ▼
             Email Platform
                    │
                    ▼
          Email Clone Detector
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
         SOC                Users
```

The detector should treat all externally received email data as untrusted input.

---

## 6. Threat Scenarios

### TM-001 — Lookalike Domain

**Description:** An attacker registers or controls a domain visually similar to a legitimate participant.

```text
supplier.com
supp1ier.com
```

**Attack Objective:** Convince recipients that the message originated from the legitimate organization.

**Detection Opportunities:** domain similarity, participant history, display name, conversation context

### TM-002 — Display Name Impersonation

**Description:** An attacker uses the display name of a legitimate participant.

| | Identity |
|---|---|
| Known | `Bob Smith <bob@supplier.com>` |
| Observed | `Bob Smith <attacker@malicious.example>` |

**Detection Opportunities:** display-name match, address mismatch, participant baseline, domain analysis

### TM-003 — Reply-To Manipulation

**Description:** The attacker causes replies to be delivered to an address controlled by the attacker.

```text
From:     bob@supplier.com
Reply-To: attacker@example.com
```

**Detection Opportunities:** From/Reply-To mismatch, historical Reply-To baseline, domain reputation, participant history

### TM-004 — Conversation Hijacking

**Description:** An attacker attempts to insert a malicious message into an existing business conversation.

Potential goals include:

- Payment redirection
- Invoice fraud
- Credential theft
- Malware delivery
- Data theft

**Detection Opportunities:** thread metadata, Message-ID, In-Reply-To, References, participant changes, sender identity, infrastructure, authentication

### TM-005 — Conversation Cloning

**Description:** An attacker reproduces portions of a legitimate conversation to create a convincing malicious message.

Potential copied elements: subject, signature, previous message content, formatting, recipient list, business terminology.

**Detection Opportunities:** content similarity, conversation history, identity mismatch, new participant, new infrastructure

### TM-006 — Compromised Legitimate Account

**Description:** An attacker sends email using a genuinely compromised account.

```text
From: legitimate-user@company.com
```

The sender identity may therefore appear valid.

**Detection Opportunities:** unusual sending time, unusual recipients, new infrastructure, behavioral anomaly, unexpected attachments, unexpected links, authentication context

**Limitation:** A legitimate account compromise may be difficult to distinguish from normal activity using email metadata alone. The detector should therefore produce contextual evidence rather than claim certainty.

### TM-007 — Authentication Manipulation

**Description:** An attacker sends messages that produce unexpected SPF, DKIM, or DMARC results.

**Detection Opportunities:** SPF, DKIM, DMARC, Authentication-Results

Authentication results should be treated as one component of a broader detection decision.

### TM-008 — Infrastructure Anomaly

**Description:** A known sender suddenly sends from infrastructure not previously associated with the sender.

Potential indicators: new IP, new ASN, new hostname, new mail server, unexpected geographic origin.

### TM-009 — Behavioral Anomaly

**Description:** The message is technically valid but deviates from established communication behavior.

Examples: unusual sending hour, unusual recipient, unusual response time, unusual attachment behavior, unusual communication frequency.

---

## 7. Attack Tree

```text
Compromise Business Conversation
│
├── Impersonate Participant
│   ├── Lookalike Domain
│   ├── Display Name Spoofing
│   └── Reply-To Manipulation
│
├── Hijack Conversation
│   ├── Clone Subject
│   ├── Clone Previous Messages
│   ├── Insert New Participant
│   └── Manipulate Thread Metadata
│
├── Abuse Legitimate Account
│   ├── Compromised Credentials
│   ├── Unusual Sending Pattern
│   └── New Infrastructure
│
└── Deliver Malicious Objective
    ├── Payment Fraud
    ├── Credential Theft
    ├── Malware
    └── Sensitive Data Theft
```

---

## 8. Security Assumptions

The initial system assumes:

1. Email messages can be collected for authorized analysis.
2. Relevant headers are available.
3. Historical messages are available to establish a baseline.
4. Email authentication results may be available.
5. Some legitimate sender history exists.
6. The detector operates within an authorized environment.

---

## 9. Limitations

The system cannot guarantee that an email is malicious.

**Legitimate Account Compromise**
An attacker using a legitimate mailbox may appear identical to the legitimate sender.

**Forwarding**
Forwarding services can change authentication and infrastructure characteristics.

**Shared Mailboxes**
Multiple legitimate users may communicate from the same address.

**Third-Party Services**
CRM, marketing, ticketing, and support systems may legitimately send messages on behalf of organizations.

**Limited Historical Data**
A new legitimate sender may initially appear anomalous.

**Sophisticated Attackers**
An attacker with extensive knowledge of the target's communication patterns may reduce detectable anomalies.

---

## 10. Defensive Response

The detector should initially focus on detection and notification, not destructive automated response.

Potential responses:

- Create SOC alert
- Create investigation event
- Notify security team
- Notify affected user
- Increase message risk
- Send event to SIEM
- Create investigation case

> Automatic deletion or quarantine should require a separate policy and authorization layer.

---

## 11. Threat Model Principle

The system should answer:

> "What evidence indicates that this message is inconsistent with the established communication context?"

rather than:

> "Can the system prove that this email is malicious?"

This distinction is important because email security detection is probabilistic and contextual.
