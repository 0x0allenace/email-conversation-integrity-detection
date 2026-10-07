# Detection Rules

## Overview

Email Conversation Integrity Detection uses deterministic detection rules to identify suspicious inconsistencies in email identity, authentication, infrastructure, conversation participation, communication behavior, and message content.

The detection engine follows an evidence-first and baseline-aware approach. Rules compare the analyzed message against explicitly supplied trusted information and, where available, persisted historical observations.

Each rule produces structured detection information including:

- Rule ID
- Rule name
- Severity
- Match status
- Risk score
- Indicators
- Details
- Structured evidence where applicable

The current detection engine contains eight rules:

| Rule | Name | Severity | Status |
|---|---|---|---|
| BEC-001 | Lookalike Domain | — | Implemented |
| BEC-002 | Reply-To Mismatch | — | Implemented |
| BEC-003 | Thread Participant Anomaly | — | Implemented |
| BEC-004 | Authentication Anomaly | — | Implemented |
| BEC-005 | Sender Infrastructure Anomaly | — | Implemented |
| BEC-006 | Conversation Hijacking | — | Implemented |
| BEC-007 | Behavioral Communication Anomaly | MEDIUM | Operational / Expanding |
| BEC-008 | Message Content Anomaly | MEDIUM | Operational |

BEC-007 and BEC-008 use historical observations supplied by the application layer. Individual detection rules do not directly access the database.

---

## BEC-001 — Lookalike Domain

**Purpose:** Detect domains that closely resemble a previously trusted sender domain.

```text
Known domain:    supplier.com
Observed domain: supp1ier.com
```

### Detection Logic

The observed sender domain is compared with the known sender domain.

A sufficiently similar but different domain can produce a detection.

The rule is intended to identify visual or structural domain similarities that may support sender impersonation.

### Indicators

Potential evidence includes:

- Known domain
- Observed domain
- Domain mismatch
- Domain similarity

### Security Context

Lookalike domains can be used to impersonate trusted organizations, suppliers, customers, or business partners.

A domain similarity detection is an indicator and should be interpreted alongside sender identity, authentication, infrastructure, conversation, and behavioral evidence.

---

## BEC-002 — Reply-To Mismatch

**Purpose:** Detect inconsistencies between the apparent sender and the Reply-To address.

```text
From:     John Smith <john@supplier.com>
Reply-To: john.supplier@gmail.com
```

### Detection Logic

The Reply-To address is compared against the apparent sender identity.

A mismatch can become a detection indicator when the reply destination differs from the expected sender identity.

### Indicators

Potential evidence includes:

- Sender email
- Reply-To email
- Sender domain
- Reply-To domain

### Security Context

Attackers may manipulate Reply-To addresses to redirect responses to an address they control while preserving a familiar sender identity in the visible From field.

> A Reply-To mismatch is not automatically malicious because legitimate forwarding, support, ticketing, and delegated-mail workflows can also produce legitimate mismatches.

---

## BEC-003 — Thread Participant Anomaly

**Purpose:** Detect unexpected participants within an established conversation.

```text
Known participants: alice@company.com, bob@supplier.com
Observed:           alice@company.com, bob@supplier.com, attacker@example.net
```

### Detection Logic

Observed conversation participants are compared against the supplied participant baseline.

A participant that is not present in the baseline can trigger the rule.

> **Important:** The participant baseline should contain all expected legitimate participants. An incomplete baseline can produce false positives.

### Indicators

Potential evidence includes:

- Known participants
- Observed participants
- Unexpected participants
- Participant differences
- Conversation-related context

### Security Context

Unexpected participants may indicate:

- Conversation manipulation
- Unauthorized forwarding
- Thread hijacking
- Accidental inclusion
- Legitimate changes to a business conversation

The participant anomaly should therefore be evaluated together with the other detection results.

---

## BEC-004 — Authentication Anomaly

**Purpose:** Evaluate available email authentication results.

### Current Authentication Signals

The current implementation considers:

- SPF
- DKIM
- DMARC

### Detection Logic

Authentication information available in the analyzed message is evaluated for anomalous or failed authentication results.

The authentication result becomes supporting evidence for the overall analysis rather than functioning as an isolated determination of malicious activity.

### Security Context

Authentication failures can provide evidence associated with:

- Spoofing
- Sender identity manipulation
- Unauthorized sending infrastructure
- Domain authentication problems

> Authentication failure alone does not establish that a message is malicious. Legitimate email infrastructure, forwarding services, configuration changes, and third-party mail systems can also produce authentication anomalies.

---

## BEC-005 — Sender Infrastructure Anomaly

**Purpose:** Detect changes in infrastructure associated with a known sender.

### Current Indicators

The current implementation evaluates:

- Previously unseen sending host
- Previously unseen sending IP address

```text
Known host:    mail.supplier.com
Observed host: new-mail.example.net
```

### Detection Logic

Observed sender infrastructure is compared against the supplied known infrastructure baseline.

Previously unseen infrastructure can produce a detection indicator.

### Security Context

A change in sender infrastructure can be relevant to impersonation and account-compromise investigations.

However, infrastructure changes can also occur for legitimate reasons, including:

- Mail-provider changes
- Cloud migration
- New mail servers
- Temporary sending services
- Third-party email platforms
- Infrastructure maintenance

### Future Enrichment

Future infrastructure enrichment may include:

- ASN
- Geographic information
- Reverse DNS
- Infrastructure reputation
- Threat-intelligence enrichment

These capabilities are not required for the current deterministic infrastructure detection.

---

## BEC-006 — Conversation Hijacking

**Purpose:** Detect suspicious messages that appear to continue an established business conversation while containing multiple inconsistencies.

### Detection Context

The rule can consider information involving:

- Sender identity
- Headers
- Infrastructure
- Authentication
- Participants
- Conversation structure

### Detection Logic

BEC-006 combines available conversation and sender indicators to identify suspicious continuation of an established conversation.

The objective is to identify combinations of inconsistencies rather than relying exclusively on a single indicator.

### Security Context

Conversation hijacking can be difficult to identify when an attacker attempts to preserve familiar:

- Subjects
- Participants
- Sender identities
- Communication context
- Conversation structure

BEC-006 therefore complements the more specialized identity, authentication, infrastructure, behavioral, and content rules.

---

## BEC-007 — Behavioral Communication Anomaly

**Purpose:** Detect communication behavior that differs from an established sender or conversation baseline.

**Severity:** MEDIUM
**Status:** Operational / Expanding

BEC-007 uses deterministic behavioral analysis based on:

- Explicitly supplied behavioral baselines
- Persisted historical sender observations
- Historical recipient relationships
- Historical communication patterns

The rule does not require machine learning.

Historical observations are retrieved by the application service and passed into the detection engine as structured data. BEC-007 remains independent of direct database access.

### Current Behavioral Signals

The current BEC-007 implementation evaluates behavioral dimensions including:

- Typical sending hour
- Typical sending day
- Typical sender-declared timezone offset
- Historical sending-hour range
- Historical sending frequency
- Historical recipient behavior
- Historical recipient frequency
- Historical recipient co-occurrence
- Historical recipient role relationships
- Historical recipient count
- Historical recipient recency
- Historical communication transitions
- Historical CC usage and recipient count
- Historical attachment usage

These signals are intentionally deterministic and explainable.

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
Established behavior:
  08:00–17:00
Observed message:
  02:47
Indicator:
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
Established behavior:
  Monday–Friday
Observed message:
  Sunday
Indicator:
- Message sent outside established communication days
```

### Timezone Offset

The optional `typical_timezone_offsets` baseline represents the UTC offsets declared in the email `Date` header.

Values are expressed in minutes.

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
Indicator:
- Message sent from an unexpected timezone offset
```

> This signal evaluates the timezone offset declared by the message's `Date` header. It does not establish the sender's physical location or prove that the sender was actually operating from that timezone.

### Historical Sender Observations

When an analyzed sender has previously persisted email observations with valid historical data, the application service retrieves those observations and supplies them to BEC-007.

A minimum of three qualifying historical observations is required before the relevant historical behavioral analysis is established.

Historical observations with missing or invalid data for a specific signal are ignored for that signal.

Historical observations can provide evidence for:

- Historical sending-hour range
- Sending frequency
- Recipient behavior
- Recipient frequency
- Recipient co-occurrence
- Recipient role relationships
- Recipient count
- Recipient recency
- Communication transitions
- CC behavior
- Attachment behavior

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

Historical observations are ordered by their persisted `email_sent_at` timestamps.

Valid consecutive observations are used to establish historical sending intervals.

A minimum of three qualifying historical observations is required before frequency-based behavioral analysis is established.

The current message is compared against the established historical communication cadence using deterministic frequency analysis.

The result can preserve structured evidence describing the observed and historical communication frequency.

> Sending frequency is an observed behavioral signal. A change in communication cadence can be legitimate and should be evaluated alongside the other detection evidence.

### Historical Recipient Behavior

BEC-007 evaluates whether the current message is addressed to recipients that have not previously appeared in the sender's established communication history.

The current recipient set is derived from the message's `To` and `Cc` fields.

Historical recipients are recovered from persisted sender analyses using the recipient data stored in each historical analysis result.

Recipient values are normalized by:

1. Removing surrounding whitespace.
2. Converting addresses to lowercase.
3. Removing duplicate addresses.
4. Ignoring non-string recipient values.

A minimum of three qualifying historical observations is required before recipient history is used as a behavioral baseline.

When a current recipient is absent from the established historical recipient set, BEC-007 can record:

```text
Message sent to a previously unseen recipient
```

The detection result can expose:

- `historical_recipients`
- `unusual_recipients`

> This signal is a behavioral anomaly indicator rather than proof of malicious activity.

### Historical Recipient Frequency

BEC-007 can evaluate how frequently individual recipients have historically appeared in the sender's communication.

Recipient frequency represents the proportion of qualifying historical observations in which a recipient appeared.

**Example:**

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

**Example:**

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

An unseen individual recipient is handled by recipient behavior analysis, while an established recipient appearing in an unusual combination can be identified by co-occurrence analysis.

> Recipient co-occurrence is an observed communication-pattern signal. Legitimate business events can create new recipient relationships.

### Historical Recipient Role Anomaly

BEC-007 evaluates whether established recipient pairs normally occupy the same `To` and `Cc` roles.

Role analysis builds on historical recipient co-occurrence and is only applied when the recipient pair is already an established relationship.

**Example:**

```text
Historical:
  To: alice@company.com
  Cc: finance@company.com

Current:
  To: finance@company.com
  Cc: alice@company.com
```

The same recipients are present and their relationship is known, but their communication roles have changed.

BEC-007 can record:

```text
Message contains a historically unusual recipient role relationship
```

Multiple recipients are supported in both `To` and `Cc` fields.

If a recipient appears in both `To` and `Cc`, the `To` role takes precedence so that each recipient has one deterministic role for analysis.

A minimum of three qualifying historical observations is required before recipient role analysis is established.

> An unseen recipient pair is handled by recipient co-occurrence analysis rather than being treated as a recipient role anomaly.

> A change in recipient role is an observed communication-pattern anomaly. Legitimate workflow changes can cause recipients to move between `To` and `Cc`.

### Additional Historical Behavioral Signals

BEC-007 also supports historical analysis of additional communication characteristics, including:

**Recipient Count**
The number of recipients in the current message can be compared against historically observed recipient counts.

**Recipient Recency**
Historical recipient relationships can be evaluated in relation to when they were most recently observed.

**Communication Transitions**
Historical communication sequences can provide evidence of unusual transitions between previously observed communication states.

**CC Usage and Recipient Count**
Historical Cc behavior and recipient-count patterns can provide additional evidence of changes in established communication structure.

**Attachment Usage**
Historical attachment behavior can provide additional evidence when the current message's attachment usage differs from established sender behavior.

These signals remain deterministic and baseline-driven.

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
- Historical signals are evaluated independently according to their own data requirements.
- An empty explicit behavioral baseline does not independently produce a behavioral detection.
- Historical analysis is performed only when sufficient valid historical observations are available for the relevant signal.

### Detection Evidence

BEC-007 exposes structured behavioral details that can support investigation, including:

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
- Historical recipient counts
- Recipient recency evidence
- Communication transition evidence
- CC usage evidence
- Attachment usage evidence

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

The currently implemented BEC-007 behavioral scope includes:

| Signal | Source | Status |
|---|---|---|
| Typical sending hour | Supplied behavioral baseline | Implemented |
| Typical sending day | Supplied behavioral baseline | Implemented |
| Typical timezone offset | Supplied behavioral baseline | Implemented |
| Historical sending-hour range | Persisted sender observations | Implemented |
| Historical sending frequency | Persisted sender observations | Implemented |
| Recipient novelty | Persisted sender observations | Implemented |
| Recipient frequency anomaly | Persisted sender observations | Implemented |
| Recipient relationship anomaly | Persisted sender observations | Implemented |
| Recipient role anomaly | Persisted sender observations | Implemented |
| Recipient count behavior | Persisted sender observations | Implemented |
| Recipient recency behavior | Persisted sender observations | Implemented |
| Communication transition behavior | Persisted sender observations | Implemented |
| CC usage behavior | Persisted sender observations | Implemented |
| Attachment usage behavior | Persisted sender observations | Implemented |

These signals are intentionally deterministic and explainable.

> BEC-007 remains an expanding behavioral rule because additional historical signals can be introduced as their observation sources, baselines, validation, and evidence models are established.

### Future Behavioral Indicators

Potential future behavioral enhancements may include:

- Response time
- Additional participant-count analysis
- Infrastructure frequency
- Domain similarity frequency
- Reply-To frequency
- Additional statistically derived behavioral features

> Subject similarity and body similarity are implemented separately by BEC-008 and are therefore not part of the BEC-007 content-analysis scope.

Future behavioral signals should only be introduced when the system has a clearly defined observation source, sufficient data, and a clearly defined baseline or statistical methodology.

---

## BEC-008 — Message Content Anomaly

**Purpose:** Detect message content and attachment characteristics that differ substantially from the sender's established historical message patterns.

**Severity:** MEDIUM
**Status:** Operational

BEC-008 provides deterministic historical content analysis.

The rule compares the current message against previously observed messages supplied through the detection context.

The current BEC-008 signals are:

- Subject similarity anomaly
- Body similarity anomaly
- Body length anomaly
- Attachment filename novelty
- Attachment size anomaly

The rule does not require machine learning or external NLP dependencies.

### Historical Content Baseline

Historical observations are retrieved by the application service and passed into the detection engine as structured data.

BEC-008 itself remains independent of the database.

The general minimum historical observation requirement is:

```text
MIN_HISTORICAL_OBSERVATIONS = 3
```

Signals are evaluated independently.

A specific signal only becomes available when sufficient qualifying historical observations exist for that signal.

Historical observations containing missing or invalid data for a specific signal are ignored for that signal.

> This prevents incomplete historical records from being treated as reliable evidence.

### Subject Similarity

BEC-008 normalizes the current subject and historical subjects before comparison.

#### Subject Normalization

Normalization includes:

1. Converting text to lowercase.
2. Removing repeated `Re:`, `Fw:`, and `Fwd:` prefixes.
3. Collapsing repeated whitespace.
4. Removing unnecessary surrounding whitespace.

**Example:**

```text
Original:
  Re: Re: Fwd: Quarterly Supplier Review
Normalized:
  quarterly supplier review
```

#### Comparison

The normalized current subject is compared against normalized historical subjects using deterministic sequence similarity based on Python's standard-library `difflib.SequenceMatcher`.

The strongest similarity result across the qualifying historical subjects is used as the comparison evidence.

The current threshold is:

```text
SUBJECT_SIMILARITY_THRESHOLD = 0.50
```

A strongest historical similarity below 0.50 can produce:

```text
Indicator:
- Message subject differs substantially from historical message patterns
```

> This signal identifies unusual changes in established subject patterns. It does not determine whether the new subject is malicious.

### Body Similarity

BEC-008 normalizes message body content before comparison.

#### Body Normalization

Normalization includes:

1. Converting text to lowercase.
2. Collapsing repeated whitespace.
3. Removing unnecessary surrounding whitespace.

The normalized current body is compared against normalized historical bodies using deterministic sequence similarity based on Python's standard-library `difflib.SequenceMatcher`.

The strongest similarity result across qualifying historical bodies is used for the signal.

The current threshold is:

```text
BODY_SIMILARITY_THRESHOLD = 0.50
```

A strongest historical similarity below 0.50 can produce:

```text
Indicator:
- Message body differs substantially from historical message patterns
```

> Body similarity is an observed content-pattern signal and should be interpreted alongside the other detection evidence.

### Body Length Anomaly

BEC-008 compares the current body length against the historical body-length baseline.

Historical body lengths are calculated from normalized body content.

The historical baseline uses the median body length.

The current threshold is:

```text
BODY_LENGTH_RATIO_THRESHOLD = 2.0
```

The current body can be considered anomalous when its length is:

- Greater than two times the historical median, or
- Less than one-half of the historical median.

**Example:**

```text
Historical body lengths:
  420
  450
  500
Historical median:
  450
Upper threshold:
  900
Lower threshold:
  225
```

A current body length of 1200 is anomalous because it exceeds twice the historical median.

A current body length of 150 is anomalous because it is less than half the historical median.

Exact boundary values are treated as normal:

```text
2.0 × median
0.5 × median
```

are not themselves outside the configured range.

### Zero-Length Historical Bodies

BEC-008 handles a zero historical median explicitly.

When:

```text
Historical median:
  0
```

a current body containing content can be considered anomalous.

This prevents the ratio comparison from attempting to divide by zero.

A current empty body remains consistent with a zero-length historical baseline.

### Attachment Analysis

BEC-008 now includes deterministic attachment analysis.

The current attachment signals are:

1. Attachment filename novelty
2. Attachment size anomaly

Attachment analysis remains historical and baseline-aware.

> It does not perform malware analysis or inspect attachment contents.

### Attachment Filename Novelty

**Purpose:** Detect attachment filenames that have not previously appeared in the sender's qualifying historical attachment baseline.

#### Current Attachment Normalization

Attachment filenames are normalized before comparison.

The normalization is used to provide deterministic comparisons between current and historical filenames.

Invalid attachment entries and invalid or empty filenames are ignored.

#### Historical Requirement

Attachment filename novelty requires at least:

```text
3 historical observations containing attachment metadata
```

Historical observations without a usable attachment list do not count toward this requirement.

Within qualifying attachment metadata:

- Non-dictionary attachment entries are ignored.
- Invalid attachment filenames are ignored.
- Empty normalized filenames are ignored.

#### Detection Logic

The current normalized attachment filenames are compared against the normalized filenames observed in the qualifying historical attachment observations.

A filename that is absent from the historical filename baseline can be considered novel.

**Example:**

```text
Historical attachment filenames:
  invoice.pdf
  invoice.pdf
  invoice.pdf
Current attachment:
  payment-instructions.pdf
Result:
- Attachment filename is historically novel
```

The detection evidence can preserve:

- Current attachment filenames
- Historical attachment filenames
- Novel attachment filenames
- Historical observation count
- Whether a sufficient attachment baseline was available

> A novel attachment filename is not proof of malicious activity. Legitimate new invoices, reports, contracts, documents, and business processes can introduce previously unseen filenames.

### Invalid Attachment Metadata

BEC-008 intentionally ignores invalid attachment metadata when evaluating filename novelty.

**For example:**

```text
Current attachments:
  {}
  {"filename": ""}
  {"filename": "invoice.pdf"}
  "invalid"
```

Only the valid attachment filename is considered.

Similarly, historical observations containing malformed attachment entries do not create artificial historical evidence.

This prevents malformed or incomplete attachment metadata from incorrectly influencing the historical baseline.

### Attachment Size Anomaly

**Purpose:** Detect an attachment whose size differs substantially from the historical size baseline for the same normalized filename.

Attachment size analysis is performed independently for each normalized attachment filename.

#### Historical Requirement

Attachment size analysis requires at least:

```text
3 valid historical size observations
```

for the same normalized attachment filename.

Historical attachment sizes are grouped by normalized filename.

Invalid historical attachment entries are ignored when:

- The attachment is not a dictionary.
- The filename is invalid or empty.
- The size is boolean.
- The size is non-numeric.

This prevents invalid values from becoming part of the historical size baseline.

### Historical Attachment Size Baseline

The historical attachment size baseline uses the median size for the same normalized filename.

**Example:**

```text
Historical:
invoice.pdf
  100 KB
  100 KB
  100 KB
Historical median:
  100 KB
```

The current attachment size is then compared against that baseline.

### Attachment Size Threshold

The current attachment size comparison uses a two-times / half-times threshold.

A current attachment size can be considered anomalous when it is:

- Greater than two times the historical median, or
- Less than one-half of the historical median.

**Example:**

```text
Historical median:
  100 KB
Upper threshold:
  200 KB
Lower threshold:
  50 KB
```

Therefore:

```text
Current:
  201 KB
Result:
- Attachment size anomaly
```

And:

```text
Current:
  49 KB
Result:
- Attachment size anomaly
```

Exact boundaries are normal:

```text
200 KB
50 KB
```

do not exceed the configured anomaly range.

### Zero Historical Attachment Size

BEC-008 handles a zero historical median explicitly.

When:

```text
Historical median:
  0
```

a current attachment with a size greater than zero can be considered anomalous.

This prevents the size-ratio comparison from attempting to divide by zero.

A current attachment size of zero remains consistent with a zero historical median.

### Per-Filename Attachment Baselines

Attachment size analysis is performed against the historical baseline for the same normalized filename.

**For example:**

```text
Historical:
invoice.pdf:
  100 KB
  100 KB
  100 KB
report.pdf:
  1 MB
  1 MB
  1 MB
```

The current:

```text
invoice.pdf:
  210 KB
```

is evaluated against the `invoice.pdf` baseline rather than the `report.pdf` baseline.

This prevents unrelated attachment types from influencing one another's size baseline.

### Invalid Current Attachment Metadata

Invalid current attachment metadata is ignored for attachment size analysis.

**For example:**

```text
Current attachments:
  {}
  {"filename": ""}
  {"filename": "invoice.pdf", "size": true}
  {"filename": "invoice.pdf", "size": "invalid"}
  {"filename": "invoice.pdf", "size": 201000}
```

Only the valid numeric attachment size is eligible for analysis.

Boolean values are not treated as numeric attachment sizes.

This keeps malformed metadata from generating misleading attachment-size detections.

### Multiple Attachment Anomalies

BEC-008 can evaluate multiple attachment-related anomalies within the same message.

**For example:**

```text
Historical:
  invoice.pdf
  invoice.pdf
  invoice.pdf
Current:
  payment-instructions.pdf
```

can produce:

```text
Indicator:
- Attachment filename is historically novel
```

Similarly:

```text
Historical invoice.pdf sizes:
  100 KB
  100 KB
  100 KB
Current invoice.pdf:
  250 KB
```

can produce:

```text
Indicator:
- Attachment size differs substantially from historical behavior
```

These signals are evaluated independently.

### Multiple Content Anomalies

BEC-008 evaluates subject, body, body length, attachment filename, and attachment size independently.

A single message can therefore produce multiple content-related indicators.

**Example:**

```text
Indicators:
- Message subject differs substantially from historical message patterns
- Message body differs substantially from historical message patterns
- Message body length differs substantially from historical message patterns
- Attachment filename is historically novel
- Attachment size differs substantially from historical behavior
```

Each indicator corresponds to a specific deterministic comparison.

This preserves the evidence-first design of the rule.

### Structured Content Evidence

BEC-008 exposes structured evidence for detected content anomalies.

**Evidence can include information such as:**

**Subject**
- Signal type
- Current normalized subject
- Historical subject comparison
- Similarity value
- Similarity threshold

**Body**
- Signal type
- Current normalized body
- Historical body comparison
- Similarity value
- Similarity threshold

**Body Length**
- Signal type
- Current body length
- Historical body lengths
- Historical median body length
- Body-length threshold
- Historical observation count

**Attachment Filename**
- Signal type
- Current attachment filenames
- Historical attachment filenames
- Novel attachment filenames
- Historical observation count
- Baseline availability

**Attachment Size**
- Signal type
- Attachment filename
- Current attachment size
- Historical attachment sizes
- Historical median size
- Size threshold
- Historical observation count

This structured evidence allows API consumers, persistence, and SIEM integrations to preserve the reasoning behind the detection.

### Content Baseline Requirements

BEC-008 uses a minimum of three qualifying observations for historical analysis.

```text
MIN_HISTORICAL_OBSERVATIONS = 3
```

However, qualification is signal-specific.

**For example:**

```text
Subject:
  Requires at least 3 valid historical subjects.
Body similarity:
  Requires at least 3 valid historical bodies.
Body length:
  Requires at least 3 valid historical body lengths.
Attachment filename novelty:
  Requires at least 3 historical observations containing attachment metadata.
Attachment size:
  Requires at least 3 valid historical size observations for the same normalized filename.
```

This means one message can have sufficient historical evidence for one signal while another signal remains unavailable.

The rule does not infer an anomaly merely because insufficient historical data exists.

### Historical Content Observation Source

Historical content observations are supplied by the application layer.

The detection rule does not query PostgreSQL directly.

The architecture is:

```text
Database
   │
   ▼
Repository
   │
   ▼
Analysis Service
   │
   ▼
Historical Observations
   │
   ▼
Detection Context
   │
   ▼
BEC-008
```

This keeps BEC-008 deterministic, testable, and independent of persistence implementation details.

### Current Content Scope

The currently implemented BEC-008 content signals are:

| Signal | Historical Source | Minimum Evidence | Status |
|---|---|---|---|
| Subject similarity anomaly | Historical message subjects | 3 valid subjects | Implemented |
| Body similarity anomaly | Historical message bodies | 3 valid bodies | Implemented |
| Body length anomaly | Historical body lengths | 3 valid lengths | Implemented |
| Attachment filename novelty | Historical attachment metadata | 3 qualifying observations | Implemented |
| Attachment size anomaly | Same filename historical sizes | 3 valid sizes | Implemented |

All five signals are deterministic and explainable.

### BEC-008 Limitations

BEC-008 is a content-pattern and attachment-metadata anomaly detector.

**It does not currently perform:**

- Semantic NLP
- Embedding-based similarity
- External AI classification
- Malware analysis
- Attachment content inspection
- Archive extraction
- File hashing for malware detection
- Threat-intelligence lookup
- Behavioral intent classification

Attachment filename and size anomalies are metadata-based indicators only.

> A content or attachment anomaly does not establish malicious intent by itself.

---

## Conversation Hijacking Analysis

Conversation hijacking detection combines multiple sources of evidence.

Potential indicators include:

- Unexpected sender identity
- Unexpected participant
- Header inconsistencies
- Infrastructure changes
- Authentication anomalies
- Conversation structure inconsistencies
- Behavioral anomalies
- Message content anomalies
- Attachment anomalies

The objective is not to rely on one indicator but to identify combinations of inconsistencies that may indicate that an established conversation has been manipulated.

---

## Detection Results

Each detection result contains structured information.

A typical detection includes:

```text
Rule ID
Rule Name
Severity
Matched
Risk Score
Indicators
Details
```

For BEC-007 and BEC-008, indicators may contain both human-readable strings and structured evidence objects.

**Example:**

```text
Rule:
  BEC-008 — Message Content Anomaly
Indicators:
  - Message subject differs substantially from historical message patterns
Structured evidence:
  - Signal type
  - Similarity value
  - Threshold
  - Historical comparison data
```

An attachment-related detection can preserve evidence such as:

```text
Rule:
  BEC-008 — Message Content Anomaly
Signal:
  attachment_size
Evidence:
  Filename:
    invoice.pdf
  Current size:
    250000
  Historical median:
    100000
  Threshold:
    2.0x
```

This allows downstream systems to preserve not only the fact that a rule matched, but also the evidence that caused the match.

---

## Severity and Risk

Each detection returns a severity value and risk contribution.

The risk score is generated from observable indicators associated with the rule.

Individual detection scores are capped at 100.

The overall analysis can combine risk contributions from matched detections.

BEC-007 and BEC-008 contribute to the analysis when their respective behavioral or content conditions are satisfied.

> Risk scores are intended to support analyst investigation and should not be treated as proof of malicious activity.

---

## Detection Evidence

Each matched rule should provide evidence through its structured result.

**Example:**

```text
Rule ID:
  BEC-001
Rule Name:
  Lookalike Domain
Matched:
  true
Indicators:
  - Domain mismatch
  - Domain similarity
Details:
  Known domain = supplier.com
  Observed domain = supp1ier.com
```

A behavioral detection can expose:

```text
Rule:
  BEC-007 — Behavioral Communication Anomaly
Historical hours:
  09:00, 10:00, 14:00
Historical range:
  09:00–14:00
Observed hour:
  03:00
Indicator:
- Message sent outside historically observed communication hours
```

A content detection can expose:

```text
Rule:
  BEC-008 — Message Content Anomaly
Signal:
  Subject similarity
Current subject:
  urgent payment instruction
Best historical match:
  quarterly supplier review
Similarity:
  0.31
Threshold:
  0.50
Indicator:
- Message subject differs substantially from historical message patterns
```

An attachment detection can expose:

```text
Rule:
  BEC-008 — Message Content Anomaly
Signal:
  Attachment size
Filename:
  invoice.pdf
Current size:
  201 KB
Historical median:
  100 KB
Threshold:
  2.0x
Indicator:
- Attachment size differs substantially from historical behavior
```

This structure allows a SOC analyst to investigate the underlying evidence rather than relying only on a risk score.

---

## Rule Independence

Detection rules are designed to operate independently.

**This provides several advantages:**

- Individual rules can be tested independently.
- New rules can be added without redesigning existing rules.
- Analysts can identify exactly which indicators triggered.
- Risk contributions can remain explainable.
- Detection results can be normalized for SIEM platforms.
- Historical behavioral and content analysis can evolve without coupling rules to database implementation details.

The application layer is responsible for retrieving historical observations and supplying them to the detection context.

---

## False Positives

Individual detection indicators can be triggered by legitimate activity.

Examples include:

- Legitimate changes to mail infrastructure
- Temporary sending services
- Forwarding systems
- Third-party mail providers
- Legitimate Reply-To addresses
- New employees joining a conversation
- Changes to normal communication schedules
- Legitimate communication outside historical sending hours
- Legitimate changes in sender timezone or working schedule
- Legitimate changes in recipient relationships
- Legitimate changes between `To` and `Cc` roles
- One-off recipients
- Low-frequency recipients
- Legitimate changes to message subjects
- Legitimate changes to message body content
- Short or unusually detailed messages
- New business processes producing different message templates
- New or previously unseen attachment filenames
- Legitimate changes in attachment sizes
- New document types or business processes

For this reason, detections should be interpreted using the complete analysis context.

> Historical behavioral and content anomalies should be treated as investigation indicators rather than proof of compromise.

---

## False Negatives

The system may fail to identify attacks when:

- The attacker uses the legitimate mailbox
- Baseline information is incomplete
- Historical observations are insufficient
- Relevant headers are unavailable
- Authentication information is missing
- Infrastructure information cannot be established
- Communication behavior closely resembles normal behavior
- Malicious content closely resembles legitimate historical content
- Historical message content is too limited to establish a reliable baseline
- Attachment metadata is unavailable or incomplete
- The attacker deliberately reproduces the sender's established communication patterns
- The attacker uses previously observed attachment names and sizes
- The attacker keeps recipient relationships consistent with historical behavior

The system therefore treats detection as an investigation aid rather than a guarantee of malicious activity.

---

## Future Rules

Potential future detection rules may include:

- Sender reputation anomaly
- Domain age anomaly
- Geographic sender anomaly
- ASN anomaly
- Additional attachment behavior analysis
- Mailbox forwarding-rule indicators
- Threat-intelligence correlation
- Additional conversation correlation
- Additional behavioral correlation
- Advanced content analysis

Future rules should maintain the same explainable structure used by the existing detection engine.

---

## Detection Philosophy

The detection engine follows several core principles:

**Evidence First**
Every detection should be supported by observable evidence.

**Baseline Aware**
Historical anomalies are meaningful only when the historical baseline is sufficiently established and representative.

**Deterministic First**
The current detection foundation uses deterministic rules before introducing statistical or machine-learning-based analysis.

**Independent Signals**
Individual signals are evaluated independently so that multiple inconsistencies can be preserved rather than collapsed into a single opaque decision.

**Explainable Results**
Detection results should communicate not only that an anomaly occurred, but also the evidence and thresholds that caused the detection.

**Database Independence**
Detection rules do not directly query the persistence layer. Historical observations are retrieved by the application layer and passed into the detection context.

**Investigation Support**
The engine is designed to assist SOC analysts and investigators rather than replace human judgment.

---

## Current Detection Rule Summary

| Rule | Detection Area | Historical Baseline | Status |
|---|---|---|---|
| BEC-001 | Lookalike domain | Supplied trusted domain | Implemented |
| BEC-002 | Reply-To mismatch | Sender identity | Implemented |
| BEC-003 | Thread participants | Supplied participant baseline | Implemented |
| BEC-004 | Authentication | SPF/DKIM/DMARC | Implemented |
| BEC-005 | Sender infrastructure | Known hosts/IPs | Implemented |
| BEC-006 | Conversation hijacking | Conversation context | Implemented |
| BEC-007 | Behavioral communication | Explicit + historical behavior | Operational / Expanding |
| BEC-008 | Message content + attachment metadata | Historical message observations | Operational |

BEC-008 currently provides deterministic coverage across:

```text
Subject Similarity
       │
       ├── Historical subjects
       │
       ▼
Body Similarity
       │
       ├── Historical bodies
       │
       ▼
Body Length
       │
       ├── Historical median
       │
       ▼
Attachment Filename Novelty
       │
       ├── Historical attachment metadata
       │
       ▼
Attachment Size Anomaly
       │
       └── Same-filename historical size baseline
```

The current rule set is intentionally designed to remain explainable, testable, and extensible as additional detection capabilities are introduced.
