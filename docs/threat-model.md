# Threat Model

## Overview

Email Conversation Integrity Detection is designed to identify suspicious email activity associated with Business Email Compromise (BEC), sender impersonation, and conversation hijacking.

The threat model focuses on attacks where an adversary attempts to make a malicious email appear to be part of a legitimate business conversation.

---

## Security Objective

**Primary objective:**

> Identify inconsistencies between an incoming email and the established identity, participants, infrastructure, authentication information, and communication behavior associated with a trusted conversation.

The system is designed to provide explainable evidence that can support SOC investigation.

---

## Assets

Relevant assets include:

- Business email conversations
- Sender identities
- Recipient identities
- Email headers
- Authentication information
- Conversation history
- Sender infrastructure information
- Detection results
- Risk scores
- SIEM events
- Persisted analysis records

---

## Threat Actors

Potential threat actors include:

**External Attackers**
Attackers operating outside the organization who attempt to impersonate employees, suppliers, customers, or other trusted contacts.

**Business Email Compromise Operators**
Attackers attempting to manipulate business communication for financial, credential, or information-theft objectives.

**Compromised Account Users**
Attackers operating from a legitimately compromised mailbox. This scenario is particularly challenging because the sender identity may appear legitimate.

**Infrastructure Operators**
Attackers controlling domains, hosts, or infrastructure used to send impersonation or malicious messages.

---

## Threat Scenarios

### T1 — Lookalike Domain

An attacker registers or controls a domain visually similar to a trusted domain.

```text
Trusted:  supplier.com
Attacker: supp1ier.com
```

**Potential detection:** BEC-001 — Lookalike Domain

### T2 — Reply-To Manipulation

An attacker uses a legitimate-looking sender identity while directing replies to another address.

```text
From:     john@supplier.com
Reply-To: john.supplier@gmail.com
```

**Potential detection:** BEC-002 — Reply-To Mismatch

### T3 — Conversation Participant Injection

An attacker inserts an unexpected participant into an established conversation.

**Potential detection:** BEC-003 — Thread Participant Anomaly

### T4 — Authentication Anomaly

An email contains authentication results that are inconsistent with expectations.

Relevant signals include:

- SPF
- DKIM
- DMARC

**Potential detection:** BEC-004 — Authentication Anomaly

### T5 — Infrastructure Change

A known sender suddenly uses previously unseen infrastructure.

Examples include:

- New sending host
- New sending IP address

**Potential detection:** BEC-005 — Sender Infrastructure Anomaly

### T6 — Conversation Hijacking

An attacker attempts to continue an existing conversation while manipulating sender identity, headers, infrastructure, participants, or other conversation characteristics.

**Potential detection:** BEC-006 — Conversation Hijacking

### T7 — Behavioral Anomaly

A message is inconsistent with established communication behavior.

The current MVP focuses on deterministic time-of-day behavior.

**Potential detection:** BEC-007 — Behavioral Communication Anomaly

---

## Attack Surface

The main attack surface includes:

```text
                    Email Message
                         │
             ┌───────────┼───────────┐
             ▼           ▼           ▼
          Headers     Identity    Content
             │           │           │
             └───────────┼───────────┘
                         ▼
                  Analysis Engine
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
         Database                   SIEM
```

External integrations introduce additional security considerations.

---

## Trust Boundaries

**Email Input Boundary**
`.eml` files enter the application through the API. The application should treat email content as untrusted input.

**Database Boundary**
Analysis results are persisted to PostgreSQL. Database credentials must be protected and should not be committed to source control.

**SIEM Boundary**
Detection events may leave the application and be transmitted to external SIEM infrastructure. SIEM credentials and tokens must be protected.

---

## Security Assumptions

The current system assumes:

- The analysis environment is authorized to inspect the supplied email.
- Known participant information is supplied by a trusted source.
- Known infrastructure information is reasonably accurate.
- The API and database environment are appropriately protected.
- SIEM credentials are stored securely.
- The analysis host is trusted.

---

## Threats to the Detection System

The detector itself can also be targeted.

**Malformed Email Input**
Attackers may provide malformed or unusual email messages. The parser should therefore handle malformed input safely and avoid assuming that headers are always present.

**Baseline Manipulation**
If an attacker can influence the known baseline, detection accuracy may be reduced.

**SIEM Credential Exposure**
SIEM tokens, usernames, passwords, and API keys must not be stored directly in source code.

**Database Exposure**
Persisted email analysis may contain sensitive metadata. Database access should therefore be restricted.

**Alert Flooding**
An attacker could generate large numbers of suspicious messages to increase alert volume. Future implementations may require rate limiting, aggregation, and alert deduplication.

---

## Mitigations

Current and planned mitigations include:

| Threat | Mitigation |
|---|---|
| Lookalike domain | Domain similarity analysis |
| Reply-To manipulation | Reply-To mismatch detection |
| Participant injection | Participant baseline analysis |
| Authentication anomalies | SPF/DKIM/DMARC analysis |
| Infrastructure changes | Host/IP baseline comparison |
| Conversation hijacking | Multi-indicator conversation analysis |
| Behavioral anomalies | Behavioral baseline comparison |
| Credential exposure | Environment-based configuration |
| Detection opacity | Explainable detection results |
| Malformed input | Structured parsing and validation |

---

## Limitations

The current system cannot guarantee detection of all email attacks.

Important limitations include:

- A compromised legitimate mailbox may appear legitimate.
- Incomplete baselines can produce false positives or false negatives.
- Missing authentication headers reduce available evidence.
- Legitimate infrastructure changes can resemble malicious activity.
- Behavioral analysis is currently deterministic and limited.
- External threat-intelligence enrichment is not currently required for detection.
- Machine-learning anomaly detection has not yet been implemented.

---

## Future Threat Modeling

Future development may extend the threat model to include:

- OAuth token compromise
- Microsoft 365 mailbox compromise
- Gmail account compromise
- Internal account takeover
- Malicious forwarding rules
- Mailbox persistence
- Advanced conversation manipulation
- Threat-intelligence correlation
- Automated mailbox monitoring

These capabilities will be considered as the system expands beyond `.eml` analysis.
