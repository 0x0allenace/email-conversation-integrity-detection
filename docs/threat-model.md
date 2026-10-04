# Threat Model

## Overview

Email Conversation Integrity Detection is designed to identify suspicious email activity associated with Business Email Compromise (BEC), sender impersonation, conversation hijacking, abnormal communication behavior, and suspicious changes in message content.

The threat model focuses on attacks where an adversary attempts to make a malicious email appear to be part of a legitimate business conversation.

The system currently analyzes `.eml` messages using deterministic, explainable detection rules. Historical sender observations can provide additional behavioral and message-content evidence when sufficient historical data is available.

---

## Security Objective

**Primary objective:**

> Identify inconsistencies between an incoming email and the established identity, participants, infrastructure, authentication information, communication behavior, and historical message-content patterns associated with a trusted conversation.

The system is designed to provide explainable evidence that can support SOC investigation.

> The system is not intended to determine maliciousness from a single signal. Individual anomalies should be evaluated together with the broader analysis context.

---

## Assets

Relevant assets include:

- Business email conversations
- Sender identities
- Recipient identities
- Email headers
- Authentication information
- Conversation history
- Historical sender observations
- Historical message-content patterns
- Sender infrastructure information
- Detection results
- Risk scores
- SIEM events
- Persisted analysis records

> Historical observations may contain sensitive communication metadata and should therefore be treated as security-relevant information.

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

### T7 — Behavioral Communication Anomaly

A message is inconsistent with established communication behavior.

The current implementation uses deterministic behavioral analysis based on supplied behavioral baselines and historical sender observations.

**Current behavioral signals include:**

- Typical sending hour
- Typical sending day
- Typical timezone offset
- Historical sending-hour range
- Historical sending frequency
- Historical recipient behavior
- Historical recipient frequency
- Historical recipient co-occurrence
- Historical recipient role relationships

Historical analysis requires sufficient valid observations for the relevant signal. A minimum of three qualifying historical observations is generally required before historical behavioral analysis is established.

**Potential detection:** BEC-007 — Behavioral Communication Anomaly

### T8 — Message Content Anomaly

An attacker changes the content of a message so that it differs substantially from the sender's established historical message patterns.

**Current BEC-008 content signals include:**

- Subject similarity anomaly
- Body similarity anomaly
- Body length anomaly

BEC-008 uses deterministic historical comparison rather than machine learning or external NLP services.

Subject and body similarity are evaluated using normalized content and Python's `difflib.SequenceMatcher`.

**The current thresholds are:**

```text
Subject similarity threshold:    0.50
Body similarity threshold:       0.50
Body length ratio threshold:     2.0
Minimum historical observations: 3
```

**Potential examples include:**

```text
Historical subject:
  Quarterly supplier review
Current subject:
  Urgent payment instruction
```

or:

```text
Historical message pattern:
  Please review the supplier invoice and confirm
  the expected payment date.
Current message:
  Please immediately update the beneficiary account
  and process the outstanding payment today.
```

**Potential detection:** BEC-008 — Message Content Anomaly

> BEC-008 does not currently analyze attachments.

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
                         │
                         ▼
                Historical Baseline
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
      Behavioral Evidence     Content Evidence
             │                       │
             └───────────┬───────────┘
                         ▼
                  Analysis Engine
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
         Database                   SIEM
```

The email itself is untrusted input.

Historical observations also represent an important security boundary because manipulation or corruption of historical analysis data can influence behavioral and content baselines.

External integrations introduce additional security considerations.

---

## Trust Boundaries

**Email Input Boundary**
`.eml` files enter the application through the API. The application should treat email content as untrusted input.

**Historical Baseline Boundary**
Historical observations are retrieved from persisted analysis records and supplied to the detection engine by the application service. The detection rules should not directly access the database.

> If historical observations are manipulated, incomplete, or corrupted, behavioral and content detection accuracy may be reduced.

**Database Boundary**
Analysis results are persisted to PostgreSQL. Database credentials must be protected and should not be committed to source control.

Persisted analysis records may contain email metadata and historical observations that require appropriate access controls.

**SIEM Boundary**
Detection events may leave the application and be transmitted to external SIEM infrastructure. SIEM credentials and tokens must be protected.

---

## Security Assumptions

The current system assumes:

- The analysis environment is authorized to inspect the supplied email.
- Known participant information is supplied by a trusted source.
- Known infrastructure information is reasonably accurate.
- Historical observations are sufficiently representative of legitimate sender behavior when used as a baseline.
- The API and database environment are appropriately protected.
- SIEM credentials are stored securely.
- The analysis host is trusted.
- Historical analysis records have not been maliciously manipulated.

---

## Threats to the Detection System

The detector itself can also be targeted.

**Malformed Email Input**
Attackers may provide malformed or unusual email messages. The parser should therefore handle malformed input safely and avoid assuming that headers are always present.

**Baseline Manipulation**
If an attacker can influence the known baseline or historical observations, detection accuracy may be reduced.

> This is particularly relevant to BEC-007 and BEC-008 because both depend on historical observations when performing behavioral or content analysis.

**Historical Baseline Poisoning**
An attacker who can influence persisted observations could attempt to introduce abnormal behavior or message content into the historical baseline.

Over time, polluted observations could make malicious activity appear normal.

> The current system does not implement dedicated historical-baseline poisoning detection.

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
| Behavioral anomalies | Behavioral baseline and historical observation comparison |
| Message content anomalies | Historical subject, body, and body-length comparison |
| Historical baseline manipulation | Trusted baseline sources and controlled observation flow |
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
- Behavioral analysis is deterministic and depends on the quality and availability of baseline data.
- Historical behavioral analysis generally requires a minimum of three qualifying observations for the relevant signal.
- Message-content analysis requires sufficient historical message observations before comparison can be established.
- Historical observations may not fully represent a sender's legitimate communication behavior or content.
- Historical baseline poisoning is not currently detected automatically.
- BEC-008 uses deterministic textual comparison rather than semantic understanding.
- Subject and body similarity thresholds may not capture all meaningful content changes.
- Attachments are currently outside the scope of BEC-008.
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
- Historical baseline poisoning detection
- Advanced semantic message-content analysis
- Attachment-based threat detection

These capabilities will be considered as the system expands beyond its current `.eml` analysis and deterministic detection scope.
