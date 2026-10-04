# Detection Rules

## Overview

Email Conversation Integrity Detection uses deterministic detection rules to identify suspicious inconsistencies in email identity, authentication, infrastructure, conversation participation, communication behavior, and message content.

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
Observed:           alice@company.com, bob@supplier.com, attacker@example.net
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

**Current implementation:** BEC-007 uses deterministic behavioral analysis based on explicitly supplied behavioral baselines and persisted historical sender observations when available.

The current behavioral signals are:

- Typical sending hour
- Typical sending day
- Typical sender-declared timezone offset
- Historical sending-hour range
- Historical sending frequency
- Historical recipient behavior
- Historical recipient frequency
- Historical recipient co-occurrence
- Historical recipient role relationships

The rule does not require machine learning.

Historical observations are retrieved by the application service and passed into the detection engine as structured data. BEC-007 remains independent of the database.

### Email Timestamp

The original email `Date` header provides the timestamp used for temporal behavioral analysis.

The persisted analysis record stores this value as `email_sent_at`, which is distinct from `analyzed_at`.

| Field | Meaning |
|---|---|
| `email_sent_at` | Timestamp declared by the original email `Date` header |
| `analyzed_at` | Timestamp when the system performed the analysis |

> The `Date` header is sender-provided email metadata. Its timestamp should therefore be treated as observed message metadata rather than independently verified evidence of the sender's physical location or actual clock time.

### Sending Hour

The optional `typical_hours` baseline defines the hours during which communication is normally expected.

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

### Historical Sender Observations

When an analyzed sender has previously persisted email observations with valid historical data, the application service retrieves those observations and supplies them to BEC-007.

A minimum of three qualifying historical observations is required before historical behavioral analysis is established.

Historical observations can provide evidence for:

- Historical sending-hour range
- Sending frequency
- Recipient frequency
- Recipient co-occurrence
- Recipient role relationships

Historical observations with missing or invalid data for a specific signal are ignored for that signal.

### Historical Sending-Hour Range

BEC-007 extracts the sending hour from valid historical `email_sent_at` timestamps.

```text
Historical observations:
  09:30
  10:30
  14:00
Historical observed range:
  09:00–14:00
```

If the current message falls outside the established historical range, BEC-007 can produce:

```text
Indicator:
- Message sent outside historically observed communication hours
```

The historical range is calculated from the minimum and maximum valid observed sending hours.

> The historical range represents observed message timestamps available to the system. It is not a guarantee that the sender always communicates within that range.

### Historical Sending Frequency

BEC-007 can compare the current sending interval against the sender's historically observed communication cadence.

Historical observations are ordered by their persisted `email_sent_at` timestamps. Valid consecutive observations are used to establish historical sending intervals.

A minimum of three qualifying historical observations is required before frequency-based behavioral analysis is established.

The current message is compared against the established historical communication cadence using deterministic frequency analysis.

This signal is intended to identify substantial deviations from an established sending cadence.

> Sending frequency is an observed behavioral signal. A change in communication cadence can be legitimate and should be evaluated alongside the other detection evidence.

### Historical Recipient Behavior

BEC-007 evaluates whether the current message is addressed to recipients that have not previously appeared in the sender's established communication history.

The current recipient set is derived from the message's `To` and `Cc` fields. Historical recipients are recovered from persisted sender analyses using the recipient data stored in each historical analysis result.

Recipient values are normalized by:

1. Removing surrounding whitespace.
2. Converting addresses to lowercase.
3. Removing duplicate addresses.
4. Ignoring non-string recipient values.

A minimum of three qualifying historical observations is required before recipient history is used as a behavioral baseline.

When a current recipient is absent from the established historical recipient set, BEC-007 records:

```text
Message sent to a previously unseen recipient
```

The detection result exposes:

- `historical_recipients`
- `unusual_recipients`

> This signal is a behavioral anomaly indicator rather than proof of malicious activity.

### Historical Recipient Frequency

BEC-007 can evaluate how frequently individual recipients have historically appeared in the sender's communication.

Recipient frequency represents the proportion of qualifying historical observations in which a recipient appeared.

**For example:**

```text
Historical observations:
  10 messages
Recipient:
  finance@company.com
Historical frequency:
  Appeared in 1 of 10 messages
  Frequency: 10%
```

A historically known recipient whose observed frequency is unusually low can provide additional behavioral evidence.

This signal is distinct from the unseen-recipient signal:

```text
Unseen recipient:
  Recipient has never appeared historically.
Low-frequency recipient:
  Recipient is known historically but appears substantially less often.
```

> A low-frequency recipient is not inherently suspicious. Legitimate one-off interactions and changes in communication patterns can produce low historical frequencies.

### Historical Recipient Co-Occurrence

BEC-007 evaluates whether recipients who appear together in the current message have historically appeared together in the sender's communication history.

The current recipient set combines normalized `To` and `Cc` recipients.

Historical recipient pairs are treated as unordered relationships:

```text
alice@example.com + bob@example.com
```

represents the same relationship as:

```text
bob@example.com + alice@example.com
```

A minimum of three qualifying historical observations is required before recipient co-occurrence analysis is established.

**For example:**

```text
Historical communication:
Message 1:
  To: alice@example.com
  Cc: finance@example.com
Message 2:
  To: alice@example.com
  Cc: finance@example.com
Message 3:
  To: alice@example.com
  Cc: finance@example.com
```

The pair:

```text
alice@example.com + finance@example.com
```

has an established historical co-occurrence relationship.

If a later message contains:

```text
To: alice@example.com
Cc: legal@example.com
```

and the pair:

```text
alice@example.com + legal@example.com
```

has not previously appeared together, BEC-007 can record:

```text
Message contains a historically unusual recipient relationship
```

An unseen individual recipient is handled by the recipient behavior signal, while an established recipient appearing in an unusual combination can be identified by co-occurrence analysis.

> Recipient co-occurrence is an observed communication-pattern signal. Legitimate business events can create new recipient relationships.

### Historical Recipient Role Anomaly

BEC-007 evaluates whether established recipient pairs normally occupy the same `To` and `Cc` roles.

Role analysis builds on historical recipient co-occurrence. It is only applied when the recipient pair is already an established relationship.

**For example**, historical messages may show:

```text
Historical:
  To: alice@company.com
  Cc: finance@company.com
```

If the current message contains:

```text
Current:
  To: finance@company.com
  Cc: alice@company.com
```

the same recipients are present and their relationship is known, but their communication roles have changed. BEC-007 can record:

```text
Message contains a historically unusual recipient role relationship
```

Multiple recipients are supported in both `To` and `Cc` fields.

**For example:**

```text
To:
  alice@company.com
  bob@company.com
Cc:
  finance@company.com
  legal@company.com
  manager@company.com
```

BEC-007 evaluates recipient relationships pairwise while preserving each recipient's current `To` or `Cc` role.

If a recipient appears in both `To` and `Cc`, the `To` role takes precedence so that each recipient has one deterministic role for analysis.

A minimum of three qualifying historical observations is required before recipient role analysis is established.

> An unseen recipient pair is handled by recipient co-occurrence analysis rather than being treated as a recipient role anomaly.

> A change in recipient role is an observed communication-pattern anomaly. Legitimate workflow changes can cause recipients to move between `To` and `Cc`.

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

Historical recipient behavior can provide additional evidence:

```text
Historical:
  alice@example.com + finance@example.com
Observed:
  alice@example.com + legal@example.com
Indicator:
- Message contains a historically unusual recipient relationship
```

Recipient role analysis can provide additional evidence:

```text
Historical:
  To: alice@example.com
  Cc: finance@example.com
Observed:
  To: finance@example.com
  Cc: alice@example.com
Indicator:
- Message contains a historically unusual recipient role relationship
```

The indicators are independently evaluated and returned together when multiple behavioral conditions are violated.

### Baseline Behavior

All explicit behavioral baselines are optional.

- If `typical_hours` is supplied, the observed sending hour is evaluated.
- If `typical_days` is supplied, the observed weekday is evaluated.
- If `typical_timezone_offsets` is supplied, the observed `Date` header timezone offset is evaluated.
- If sufficient historical sender observations are available, the historical sending-hour range is evaluated.
- If sufficient historical observations contain valid timestamps, historical sending frequency is evaluated.
- If sufficient historical observations contain usable recipient data, historical recipient behavior is evaluated.
- An empty explicit behavioral baseline does not independently produce a behavioral detection.
- Historical analysis is performed only when sufficient valid historical observations are available for the relevant signal.

### Detection Evidence

The rule exposes structured behavioral details including:

- Observed hour
- Typical hours
- Observed weekday
- Typical days
- Observed timezone offset
- Typical timezone offsets
- Historical observed hours
- Historical observed-hour range
- Historical sending frequency
- Historical recipients
- Unusual recipients
- Historical recipient frequencies
- Unusual recipient frequencies
- Historical recipient co-occurrences
- Unusual recipient pairs
- Historical recipient role frequencies
- Unusual recipient role pairs
- Behavioral indicators

The persisted analysis record also preserves `email_sent_at`, allowing the original message timestamp to remain available for historical analysis.

### Historical Observation Source

Historical sender observations are retrieved by the application layer rather than directly by the BEC-007 rule.

The flow is:

```text
Persisted Analysis Records
          │
          ▼
Analysis Repository
          │
          ▼
Analysis Service
          │
          ▼
Detection Engine
          │
          ▼
DetectionContext
          │
          ▼
BEC-007
```

This separation keeps the detection rule focused on evaluating evidence while keeping database access inside the application and repository layers.

### Current Behavioral Scope

The currently implemented BEC-007 behavioral signals are:

| Signal | Source | Status |
|---|---|---|
| Typical sending hour | Supplied behavioral baseline | Implemented |
| Typical sending day | Supplied behavioral baseline | Implemented |
| Typical timezone offset | Supplied behavioral baseline | Implemented |
| Historical sending-hour range | Persisted sender observations | Implemented |
| Historical sending frequency | Persisted sender observations | Implemented |
| Historical recipient behavior | Persisted sender observations | Implemented |
| Historical recipient frequency | Persisted sender observations | Implemented |
| Historical recipient co-occurrence | Persisted sender observations | Implemented |
| Historical recipient role anomaly | Persisted sender observations | Implemented |

These signals are intentionally deterministic and explainable.

### Future Behavioral Indicators

Potential future behavioral enhancements may include:

- Response time
- Participant count
- Subject similarity
- Body similarity
- Attachment frequency
- Infrastructure frequency
- Domain similarity
- Reply-To frequency
- Additional statistically derived behavioral features

> Future behavioral signals should only be introduced when the system has a clearly defined observation source, sufficient data, and a clearly defined baseline or statistical methodology for that signal.

---

## BEC-008 — Message Content Anomaly

**Purpose:** Detect message content that differs substantially from the sender's established historical message patterns.

**Severity:** MEDIUM

BEC-008 uses deterministic historical content analysis. The rule compares the current message against previously observed messages supplied through the detection context.

The current content signals are:

- Subject similarity anomaly
- Body similarity anomaly
- Body length anomaly

The rule does not require machine learning or external NLP dependencies.

### Historical Content Baseline

Historical observations are retrieved by the application service and passed into the detection engine as structured data.

BEC-008 itself remains independent of the database.

A minimum of three valid historical observations is required before the relevant content signal is evaluated.

Historical observations with missing or invalid content for a specific signal are ignored for that signal.

### Subject Similarity

BEC-008 normalizes the current subject and historical subjects before comparison.

Subject normalization includes:

1. Converting text to lowercase.
2. Removing repeated `Re`, `Fw`, and `Fwd` prefixes.
3. Collapsing repeated whitespace.

The normalized current subject is compared against normalized historical subjects using deterministic sequence similarity based on Python's standard-library `difflib.SequenceMatcher`.

The strongest similarity result across the qualifying historical subjects is used for the signal.

The current threshold is:

```text
SUBJECT_SIMILARITY_THRESHOLD = 0.50
```

A sufficiently low similarity can produce:

```text
Indicator:
- Subject differs substantially from historical message subjects
```

> This signal is intended to identify unusual changes in established subject patterns. It does not determine whether the new subject is malicious.

### Body Similarity

BEC-008 normalizes message body content before comparison.

Body normalization includes:

1. Converting text to lowercase.
2. Collapsing repeated whitespace.

The normalized current body is compared against normalized historical bodies using deterministic sequence similarity based on Python's standard-library `difflib.SequenceMatcher`.

The strongest similarity result across the qualifying historical bodies is used for the signal.

The current threshold is:

```text
BODY_SIMILARITY_THRESHOLD = 0.50
```

A sufficiently low similarity can produce:

```text
Indicator:
- Message body differs substantially from historical message bodies
```

> Body similarity is an observed content-pattern signal and should be interpreted alongside other detection evidence.

### Body Length Anomaly

BEC-008 also compares the current body length against the historical body-length baseline.

The historical baseline uses the median length of qualifying historical message bodies.

The current threshold is:

```text
BODY_LENGTH_RATIO_THRESHOLD = 2.0
```

A body can be considered anomalous when its length is:

- More than two times the historical median, or
- Less than half the historical median.

**For example:**

```text
Historical median body length:
  500 characters
Current body:
  1,200 characters
Result:
- Message body length differs substantially from historical behavior
```

> A zero historical median is handled separately. If the historical median body length is zero and the current body contains content, the body-length signal can be considered anomalous.

### Multiple Content Anomalies

BEC-008 evaluates the content signals independently.

A single message can therefore produce multiple structured indicators:

```text
Indicators:
- Subject differs substantially from historical message subjects
- Message body differs substantially from historical message bodies
- Message body length differs substantially from historical behavior
```

The detection remains explainable because each indicator corresponds to a specific deterministic comparison.

### Structured Evidence

BEC-008 exposes structured evidence for each detected content anomaly.

The detection result can preserve information including:

- Signal type
- Historical comparison values
- Similarity evidence
- Historical body lengths
- Current body length
- Historical median body length
- Threshold information

The structured evidence allows API consumers, persistence, and SIEM integrations to preserve the reasoning behind the detection.

### Content Baseline Limitations

Message content can legitimately change because of:

- New business activities
- New projects
- Changes in communication style
- Different recipients
- New workflows
- One-time business events

> Therefore, a content anomaly is not proof of malicious activity.

The quality and representativeness of the historical message baseline directly affect detection accuracy.

### Attachments

Attachment analysis is currently outside the scope of BEC-008.

**Future attachment-focused detection may consider:**

- Attachment frequency
- Attachment type changes
- Filename patterns
- Unusual attachment sizes
- Historical attachment behavior
- Malicious attachment indicators

> These capabilities should be introduced as separate, clearly defined detection signals or rules rather than assumed to be part of the current BEC-008 implementation.

### Current Content Scope

The currently implemented BEC-008 signals are:

| Signal | Source | Status |
|---|---|---|
| Subject similarity anomaly | Historical message subjects | Implemented |
| Body similarity anomaly | Historical message bodies | Implemented |
| Body length anomaly | Historical message body lengths | Implemented |

All three signals are deterministic and explainable.

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
- Mailbox forwarding-rule indicators
- Threat-intelligence correlation
- Additional conversation and behavioral correlation rules

Future rules should maintain the same explainable structure used by the existing detection engine.
