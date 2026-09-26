# Detection Rules

## Overview

Email Conversation Integrity Detection uses deterministic detection rules to identify suspicious inconsistencies in email identity, authentication, infrastructure, conversation participation, and communication behavior.

Each rule produces structured detection information including:

- Rule ID
- Rule name
- Severity
- Match status
- Risk score
- Indicators
- Details

---

## BEC-001 — Lookalike Domain

**Purpose:** Detect domains that closely resemble a previously trusted sender domain.

```text
Known domain:    supplier.com
Observed domain: supp1ier.com
```

**Detection Logic:** The observed sender domain is compared with the known domain. A sufficiently similar but different domain can produce a detection.

**Indicators:**

- Known domain
- Observed domain
- Domain mismatch
- Domain similarity

**Security Context:** Lookalike domains can be used to impersonate trusted organizations or business partners.

---

## BEC-002 — Reply-To Mismatch

**Purpose:** Detect inconsistencies between the apparent sender and the Reply-To address.

```text
From:     John Smith <john@supplier.com>
Reply-To: john.supplier@gmail.com
```

**Detection Logic:** The Reply-To address is compared against the sender identity. A mismatch can become a detection indicator.

**Indicators:**

- Sender email
- Reply-To email
- Sender domain
- Reply-To domain

**Security Context:** Attackers may manipulate Reply-To addresses to redirect responses to an address they control.

---

## BEC-003 — Thread Participant Anomaly

**Purpose:** Detect unexpected participants within an established conversation.

```text
Known participants: alice@company.com, bob@supplier.com
Observed:            alice@company.com, bob@supplier.com, attacker@example.net
```

**Detection Logic:** Observed participants are compared against the supplied participant baseline. A participant that is not present in the baseline can trigger the rule.

> **Important:** The participant baseline must contain all expected legitimate participants. An incomplete baseline can produce false positives.

**Security Context:** Unexpected participants may indicate conversation manipulation, unauthorized forwarding, or thread hijacking.

---

## BEC-004 — Authentication Anomaly

**Purpose:** Evaluate available email authentication results.

**Signals:** The current implementation considers:

- SPF
- DKIM
- DMARC

**Detection Logic:** Authentication information available in the analyzed message is evaluated for anomalous or failed authentication results.

**Security Context:** Authentication failures can provide supporting evidence of spoofing or sender identity manipulation. Authentication anomalies should be interpreted alongside other indicators because legitimate mail infrastructure can also produce authentication failures.

---

## BEC-005 — Sender Infrastructure Anomaly

**Purpose:** Detect changes in infrastructure associated with a known sender.

**Current indicators:**

- Previously unseen sending host
- Previously unseen sending IP address

```text
Known host:    mail.supplier.com
Observed host: new-mail.example.net
```

**Detection Logic:** Observed infrastructure is compared against the supplied known infrastructure baseline.

**Future enrichment:**

- ASN
- Geographic origin
- Reverse DNS
- Infrastructure reputation
- Threat-intelligence enrichment

---

## BEC-006 — Conversation Hijacking

**Purpose:** Detect suspicious messages that appear to continue an established business conversation while containing multiple inconsistencies.

**Detection context** — the rule can consider information involving:

- Sender identity
- Headers
- Infrastructure
- Authentication
- Participants
- Conversation structure

**Detection Logic:** The rule combines available conversation and sender indicators to identify suspicious continuation of an established conversation.

**Security Context:** Conversation hijacking can be particularly difficult to identify when an attacker attempts to preserve familiar subjects, participants, and communication context.

---

## BEC-007 — Behavioral Communication Anomaly

**Purpose:** Detect communication behavior that differs from an established sender or conversation baseline.

**Current implementation:** The MVP uses deterministic temporal behavioral analysis based on the supplied communication baseline.

The current behavioral signals are:

- Sending hour
- Day of week
- Sender-declared timezone offset

The rule compares the observed message timestamp against the supplied baseline.

### Sending Hour

```text
Established behavior:   08:00–17:00
Observed message:       02:47

Result:
- Message sent outside established communication hours
```

The `typical_hours` baseline uses Python's integer hour representation:

| Value | Time |
|---|---|
| 0 | 00:00 |
| 8 | 08:00 |
| 17 | 17:00 |
| 23 | 23:00 |

### Day of Week

The optional `typical_days` baseline uses Python weekday numbering:

| Value | Day |
|---|---|
| 0 | Monday |
| 1 | Tuesday |
| 2 | Wednesday |
| 3 | Thursday |
| 4 | Friday |
| 5 | Saturday |
| 6 | Sunday |

**Example:**

```text
Established behavior:   Monday–Friday
Observed message:       Sunday

Result:
- Message sent outside established communication days
```

### Timezone Offset

The optional `typical_timezone_offsets` baseline represents the UTC offsets declared in the email `Date` header. Values are expressed in minutes:

| Date header offset | Baseline value |
|---|---|
| +0000 | 0 |
| +0100 | 60 |
| +0530 | 330 |
| -0500 | -300 |

**Example:**

```text
Established behavior:
  Timezone offsets: +0100

Observed message:
  Date header offset: -0500

Result:
- Message sent from an unexpected timezone offset
```

> This signal evaluates the timezone offset declared by the message's `Date` header. It does not establish the sender's physical location or prove that the sender was actually operating from that timezone.

### Multiple Behavioral Anomalies

BEC-007 can report more than one behavioral inconsistency for the same message.

```text
Established behavior:
  Hours:             08:00–17:00
  Days:              Monday–Friday
  Timezone offsets:  +0100

Observed:
  Sunday 02:30 -0500

Indicators:
- Message sent outside established communication hours
- Message sent outside established communication days
- Message sent from an unexpected timezone offset
```

### Baseline Behavior

All behavioral baselines are optional.

- If `typical_hours` is supplied, the observed sending hour is evaluated.
- If `typical_days` is supplied, the observed weekday is evaluated.
- If `typical_timezone_offsets` is supplied, the observed `Date` header timezone offset is evaluated.

> An empty baseline does not independently produce a behavioral detection.

This allows existing API clients that only provide `typical_hours` to remain compatible while enabling richer behavioral baselines.

### Detection Evidence

The rule exposes structured behavioral details including:

- Observed hour
- Typical hours
- Observed weekday
- Typical days
- Observed timezone offset
- Typical timezone offsets
- Behavioral indicators

### Future Behavioral Indicators

- Sender frequency
- Recipient frequency
- Response time
- Participant count
- Subject similarity
- Body similarity
- Attachment frequency
- Sender infrastructure frequency
- Domain similarity
- Reply-To frequency

> Future behavioral signals should only be introduced when the system has a clearly defined observation source or baseline for that signal.

---

## Severity and Risk

Each detection returns a severity value and risk contribution.

The risk score is generated from observable indicators associated with the rule. Individual detection scores are capped at 100.

The overall analysis can combine risk contributions from matched detections.

> The score is intended to support analyst investigation and should not be treated as proof of malicious activity.

---

## Detection Evidence

Each matched rule should provide evidence through its structured result.

```text
Rule ID:    BEC-001
Rule Name:  Lookalike Domain
Matched:    true
Indicators:
- Domain mismatch
- Domain similarity
Details:
Known domain = supplier.com
Observed domain = supp1ier.com
```

This structure allows downstream API consumers and SIEM integrations to preserve the reasoning behind the detection.

---

## Rule Independence

Detection rules are designed to operate independently. This provides several advantages:

- Individual rules can be tested independently.
- New rules can be added without redesigning existing rules.
- Analysts can identify exactly which indicators triggered.
- Risk contributions can remain explainable.
- Detection results can be normalized for SIEM platforms.

---

## Future Rules

Potential future detection rules may include:

- Sender reputation anomaly
- Domain age anomaly
- Geographic sender anomaly
- ASN anomaly
- Attachment behavior anomaly
- Unusual recipient relationship
- Conversation timing anomaly
- Message similarity anomaly
- Mailbox forwarding-rule indicators
- Threat-intelligence correlation

Future rules should maintain the same explainable structure used by the existing detection engine.
