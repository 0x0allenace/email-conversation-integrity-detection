# Detection Methodology

## Overview

Email Conversation Integrity Detection uses a layered and explainable detection methodology.

The system compares an analyzed email against supplied baselines representing known sender identity, participants, infrastructure, and communication behavior. Where historical observations are available, the system can also compare the current message against previously observed communication behavior and historical message content.

The objective is to identify inconsistencies that may indicate Business Email Compromise (BEC), sender impersonation, conversation hijacking, abnormal communication behavior, or suspicious changes in message content and attachment behavior.

The methodology prioritizes deterministic, explainable detection rules before statistical or machine-learning-based anomaly detection.

**The current detection model combines:**

- Explicit trusted baselines
- Historical observations
- Deterministic comparison logic
- Signal-specific minimum observation requirements
- Structured detection evidence
- Explainable risk scoring

Detection rules do not directly access the database. Historical observations are retrieved by the application layer and supplied to the detection engine as structured data.

---

## Detection Pipeline

```text
Incoming Email
      │
      ▼
Email Parsing
      │
      ▼
Header Extraction
      │
      ▼
Identity Analysis
      │
      ├───────────────┐
      ▼               ▼
Authentication   Infrastructure
   Analysis         Analysis
      │               │
      └───────┬───────┘
              ▼
       Conversation Analysis
              │
              ▼
       Behavioral Analysis
              │
              ├── Supplied Behavioral Baseline
              │
              └── Historical Sender Observations
              │
              ▼
       Message Content Analysis
              │
              ├── Historical Subject Patterns
              ├── Historical Body Patterns
              ├── Historical Body Length
              ├── Historical Attachment Names
              └── Historical Attachment Sizes
              │
              ▼
       Detection Rules
              │
              ▼
         Risk Scoring
              │
              ▼
       Detection Results
              │
              ▼
       Persistence
              │
              ▼
       Optional SIEM
          Dispatch
```

---

## Baseline-Based Detection

The detection engine uses known information as a comparison baseline.

Examples include:

- Known sender domain
- Known sender display name
- Known participants
- Known sending hosts
- Known IP addresses
- Known communication behavior

Historical observations provide an additional evidence source for behavioral and message-content analysis.

The baseline should represent legitimate communication patterns as accurately as possible.

Where persisted historical observations are available, they provide additional evidence without requiring individual detection rules to access the database directly.

> Poor, incomplete, or inaccurate baseline information can produce false positives, false negatives, or reduce the amount of historical evidence available to the detection engine.

---

## Identity Analysis

Identity analysis examines the relationship between the observed sender and the known sender identity.

Relevant fields include:

- Email address
- Domain
- Display name

The analysis looks for inconsistencies such as:

```text
Known:
  john@supplier.com
Observed:
  john@supp1ier.com
```

A matching display name does not establish that the underlying sender identity is legitimate.

Identity evidence is evaluated together with authentication, infrastructure, conversation, behavioral, and content signals.

---

## Domain Similarity

Lookalike-domain detection compares the observed sender domain with the trusted domain.

```text
Trusted:
  supplier.com
Observed:
  supp1ier.com
```

The purpose is to identify visually similar domains that could be used for sender impersonation.

The current implementation uses deterministic domain similarity logic.

Domain similarity is treated as an indicator rather than automatic proof of malicious activity.

---

## Reply-To Analysis

The Reply-To address is compared with the apparent sender identity.

```text
From:
  John Smith <john@supplier.com>
Reply-To:
  john.supplier@gmail.com
```

A mismatch can indicate that replies may be redirected away from the apparent sender.

The mismatch is treated as an indicator rather than automatic proof of malicious activity.

---

## Participant Analysis

The system compares observed conversation participants with the supplied participant baseline.

```text
Known participants:
  alice@company.com
  bob@supplier.com
Observed:
  alice@company.com
  bob@supplier.com
  attacker@example.net
```

The additional participant can become a detection indicator.

The baseline should include all legitimate participants expected within the conversation.

Participant anomalies can become more significant when combined with other indicators such as sender identity changes, infrastructure changes, behavioral anomalies, or message-content anomalies.

---

## Authentication Analysis

The system extracts and evaluates available authentication information.

Current authentication signals include:

- SPF
- DKIM
- DMARC

Authentication results provide supporting evidence for detection rules.

> Authentication failure alone does not necessarily establish that a message is malicious because legitimate email infrastructure can produce authentication anomalies.

Authentication evidence should therefore be interpreted alongside sender identity, infrastructure, conversation, behavioral, and content evidence.

---

## Infrastructure Analysis

Infrastructure analysis compares observed sender infrastructure against known infrastructure.

**Current indicators include:**

- Sending host
- Sending IP address

**For example:**

```text
Known host:
  mail.supplier.com
Observed host:
  new-mail.example.net
```

A previously unseen host or IP address can increase suspicion when combined with other indicators.

The current implementation focuses on previously unseen infrastructure.

**Future infrastructure enrichment may include:**

- ASN
- Geographic information
- Reverse DNS
- Infrastructure reputation

These enrichment capabilities are not required for the current deterministic detection methodology.

---

## BEC-007 — Behavioral Communication Anomaly

BEC-007 evaluates whether a message's communication behavior differs from an established sender or conversation baseline.

The current implementation uses deterministic behavioral analysis based on:

- Explicitly supplied behavioral baselines
- Historical sender observations

The rule does not require machine learning.

Historical observations are retrieved by the application service from persisted analysis records and passed into the detection engine as structured data. BEC-007 itself remains independent of the database.

**The current behavioral methodology includes signals related to:**

- Typical sending hours
- Typical sending days
- Sender-declared timezone offset
- Historical sending-hour range
- Historical sender behavior
- Historical recipient behavior
- Historical sending frequency
- Historical recipient frequency
- Historical recipient co-occurrence
- Historical recipient group relationships
- Historical recipient role relationships
- Historical individual recipient role relationships
- Historical recipient count
- Historical recipient recency
- Historical recipient communication transitions
- Historical CC usage and recipient count
- Historical attachment usage

Historical signals are evaluated only when sufficient qualifying observations exist for the relevant signal.

### Email Timestamp

The original email `Date` header is parsed during analysis and preserved as `email_sent_at` in the persisted analysis record.

This timestamp is distinct from `analyzed_at`.

| Field | Meaning |
|---|---|
| `email_sent_at` | Timestamp declared by the original email `Date` header |
| `analyzed_at` | Timestamp when the system performed the analysis |

Preserving `email_sent_at` provides an observation point for historical behavioral analysis.

> The `Date` header is sender-provided email metadata. Its timestamp should therefore be treated as observed message metadata rather than independently verified evidence of the sender's physical location or actual clock time.

### Sending Hour

The `typical_hours` baseline defines the hours during which communication is normally expected.

The observed hour is extracted from the parsed email `Date` header.

```text
Established behavior:
  Hours: 08:00–17:00
Observed:
  02:30
Indicator:
  - Message sent outside established communication hours
```

The baseline uses Python's integer hour representation:

| Value | Time |
|---|---|
| 0 | 00:00 |
| 8 | 08:00 |
| 17 | 17:00 |
| 23 | 23:00 |

This is a deterministic comparison against the supplied behavioral baseline.

### Day of Week

The optional `typical_days` baseline defines the expected communication days.

Python weekday numbering is used:

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
  Days: Monday–Friday
Observed:
  Sunday
Indicator:
  - Message sent outside established communication days
```

### Timezone Offset

The optional `typical_timezone_offsets` baseline defines the UTC offsets normally declared in the email `Date` header.

The observed offset is extracted from the parsed timestamp and represented in minutes.

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
Observed:
  Date header offset: -0500
Indicator:
  - Message sent from an unexpected timezone offset
```

> This signal evaluates the timezone offset declared by the email's `Date` header. It does not determine the sender's physical location or prove that the sender was actually operating from that timezone.

### Historical Sender Observations

When an analyzed sender has previously persisted email observations with a valid `email_sent_at` timestamp, the application service retrieves those observations and supplies them to BEC-007.

BEC-007 can use those observations to establish historical communication patterns.

A minimum of three valid historical observations is required before historical behavioral analysis is established for the relevant signal.

Historical observations with missing or invalid data for a specific signal are ignored for that signal.

> This prevents incomplete historical records from automatically becoming behavioral anomalies.

### Historical Sending-Hour Range

A minimum of three valid historical observations is required before a historical sending-hour range is established.

**For example:**

```text
Historical sending hours:
  09
  10
  14
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

A minimum of three historical observations is required before frequency-based behavioral analysis is established.

The current message is compared against the established historical communication cadence using deterministic frequency analysis.

This signal can identify substantial deviations from an established sending cadence, such as a message being sent considerably sooner than historically observed communication intervals.

The result can preserve structured evidence describing the observed and historical communication frequency.

> Sending frequency is an observed behavioral signal. A change in communication cadence can be legitimate and should be evaluated alongside the other detection evidence.

### Historical Recipient Behavior

BEC-007 evaluates whether the current message is addressed to recipients that have not previously appeared in the sender's established communication history.

The current recipient set is derived from the message's `To` and `Cc` fields.

Historical recipients are recovered from persisted sender analyses using recipient information stored in historical analysis results.

Recipient values are normalized before comparison by:

1. Removing surrounding whitespace.
2. Converting addresses to lowercase.
3. Removing duplicate addresses.
4. Ignoring non-string recipient values.

A minimum of three qualifying historical observations is required before recipient history is used as a behavioral baseline.

Historical observations without usable `To` or `Cc` recipient data do not count toward this threshold.

When a current recipient is absent from the established historical recipient set, BEC-007 can record:

```text
Message sent to a previously unseen recipient
```

The detection can also preserve:

- Historical recipients
- Unusual recipients

> A previously unseen recipient is a behavioral anomaly indicator rather than proof of malicious activity. New customers, colleagues, suppliers, or business relationships can legitimately introduce new recipients.

### Historical Recipient Frequency

BEC-007 can evaluate how frequently individual recipients have historically appeared in the sender's communication.

Recipient frequency is calculated from qualifying historical observations containing usable `To` or `Cc` recipient data.

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

This allows the detection engine to distinguish between:

```text
Unseen recipient:
  Recipient has never appeared historically.
Low-frequency recipient:
  Recipient is known historically but appears relatively infrequently.
```

The distinction allows recipient behavior to be represented with more granular evidence.

> A low-frequency recipient is not inherently suspicious. Legitimate one-off business interactions can produce low historical frequencies.

### Historical Recipient Co-Occurrence

BEC-007 evaluates whether recipients who appear together in the current message have historically appeared together in the sender's communication history.

The current recipient set combines normalized `To` and `Cc` recipients.

Historical recipient pairs are generated from qualifying historical observations.

Recipient pairs are treated as unordered relationships:

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

has an established historical relationship.

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

> Recipient co-occurrence is an observed communication-pattern signal. Legitimate business events can create new recipient relationships.

### Historical Recipient Role Relationships

BEC-007 evaluates whether established recipient relationships normally occupy the same `To` and `Cc` roles.

This analysis builds on historical recipient relationships.

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

the same recipients are present, but their communication roles have changed.

BEC-007 can record:

```text
Message contains a historically unusual recipient role relationship
```

Recipient roles are derived from the current `To` and `Cc` fields.

A minimum of three qualifying historical observations is required before recipient role analysis is established.

> An unseen recipient relationship is handled by recipient co-occurrence analysis rather than being treated as a recipient role anomaly.

> A change in recipient role is an observed communication-pattern anomaly. Legitimate workflow changes can cause recipients to move between `To` and `Cc`.

### Historical Individual Recipient Role Relationships

BEC-007 can also evaluate historical role behavior for individual recipients.

This provides a more granular behavioral baseline than pair-level role analysis.

**For example**, historical communication may establish that `finance@company.com` normally appears in the `Cc` role.

If the same recipient later appears in the `To` role, the change can provide additional behavioral evidence.

The analysis remains deterministic and is based on the roles observed in qualifying historical messages.

### Historical Recipient Count

Recipient count provides an additional behavioral dimension based on the number of recipients observed in the current message compared with historical communication patterns.

The relevant recipient set is derived from the normalized `To` and `Cc` fields.

Historical recipient counts can provide evidence of an unusual change in the size of the communication group.

**For example:**

```text
Historical pattern:
  2–3 recipients
Current message:
  12 recipients
Indicator:
  Unusual recipient count
```

The signal is interpreted as behavioral evidence rather than proof of compromise.

### Historical Recipient Recency

BEC-007 can use the temporal relationship between historical observations and recipient communication patterns as behavioral evidence.

Historical observations provide the time context required to determine whether a recipient relationship is established, recent, or unusually distant from the sender's normal communication history.

The signal is intended to supplement recipient novelty, frequency, and relationship analysis rather than replace them.

### Historical Communication Transitions

BEC-007 can preserve communication transitions observed across historical sender messages.

Communication transitions can represent changes in recipient relationships or message composition across successive observations.

These transitions provide additional context when evaluating whether the current message represents a significant departure from established communication behavior.

### Historical CC Usage and Recipient Count

BEC-007 also considers historical patterns involving `Cc` usage and recipient count.

Changes in how a sender uses the `Cc` field can provide additional behavioral evidence.

**For example:**

```text
Historical pattern:
  Cc normally contains 0–1 recipients
Current message:
  Cc contains 6 recipients
```

This can be evaluated as an unusual communication pattern when sufficient historical evidence exists.

### Historical Attachment Usage

BEC-007 can use historical attachment usage as part of sender communication behavior.

The objective is to identify changes in whether attachments are normally present in the sender's communication pattern.

This signal is separate from the detailed attachment filename and attachment-size analysis performed by BEC-008.

> BEC-007 therefore focuses on behavioral attachment usage, while BEC-008 evaluates specific attachment metadata against historical content baselines.

### Multiple Behavioral Anomalies

BEC-007 evaluates behavioral signals independently.

A single message can therefore produce multiple behavioral indicators.

**For example:**

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

Historical observations can provide additional evidence:

```text
Historical range:
  09:00–14:00
Observed:
  02:30
Indicator:
  - Message sent outside historically observed communication hours
```

Recipient behavior can provide additional evidence:

```text
Historical relationship:
  alice@example.com + finance@example.com
Observed:
  alice@example.com + legal@example.com
Indicator:
  - Message contains a historically unusual recipient relationship
```

This allows multiple independent behavioral signals to contribute to the same detection result.

### Behavioral Baseline Requirements

Explicit behavioral baselines are optional.

- If `typical_hours` is supplied, the observed sending hour is evaluated.
- If `typical_days` is supplied, the observed weekday is evaluated.
- If `typical_timezone_offsets` is supplied, the observed `Date` header timezone offset is evaluated.
- If sufficient historical sender observations are available, historical sending-hour behavior can be evaluated.
- If sufficient historical observations contain usable timestamps, historical sending frequency can be evaluated.
- If sufficient historical observations contain usable recipient data, recipient behavior can be evaluated.
- If sufficient historical observations contain attachment information, attachment usage can be evaluated.
- An empty explicit behavioral baseline does not independently produce a behavioral detection.
- Historical analysis is only performed when sufficient valid observations exist for the relevant signal.

### Behavioral Evidence

BEC-007 can expose structured behavioral evidence including:

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
- Historical recipient relationships
- Unusual recipient relationships
- Historical recipient role relationships
- Unusual recipient role relationships
- Recipient count
- CC usage
- Attachment usage
- Behavioral indicators

This evidence allows downstream persistence and SIEM integrations to retain more context than a simple matched/not-matched result.

---

## BEC-008 — Message Content Anomaly

BEC-008 evaluates whether the current message differs substantially from the sender's established historical message and attachment patterns.

**The current implementation evaluates:**

- Subject similarity
- Body similarity
- Body length
- Attachment filename novelty
- Attachment size anomaly

BEC-008 is deterministic and does not require machine learning.

The rule does not directly access the database. Historical message observations are retrieved by the application layer and supplied to the detection engine as structured data.

> BEC-008 is a content and attachment anomaly detector, not a semantic classifier or malware-analysis engine. A content or attachment anomaly does not establish malicious intent by itself.

### Historical Content Baseline

Historical message observations are retrieved by the application service and passed to the detection engine.

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
Historical Observations
          │
          ▼
Detection Engine
          │
          ▼
BEC-008
```

A minimum of three qualifying historical observations is required before the relevant historical content signal is evaluated.

Different signals require different forms of valid historical data.

| Signal | Minimum historical requirement |
|---|---|
| Subject similarity | 3 valid historical observations |
| Body similarity | 3 valid historical observations |
| Body length | 3 valid historical observations |
| Attachment filename novelty | 3 historical observations containing attachment metadata |
| Attachment size anomaly | 3 valid size observations for the same normalized filename |

Signals are evaluated independently.

### Subject Normalization

Before subject comparison, BEC-008 normalizes the current and historical subjects.

Normalization includes:

1. Converting the subject to lowercase.
2. Removing repeated `Re:`, `Fw:`, and `Fwd:` prefixes.
3. Collapsing repeated whitespace.
4. Removing unnecessary surrounding whitespace.

**For example:**

```text
Original:
  Re: Re: Fwd: Quarterly Supplier Review
Normalized:
  quarterly supplier review
```

The purpose is to avoid treating ordinary reply or forwarding prefixes as meaningful content differences.

### Subject Similarity

BEC-008 compares the normalized current subject against normalized historical subjects.

The current implementation uses Python's standard-library `difflib.SequenceMatcher`.

Similarity is represented between:

```text
0.0 = low sequence similarity
1.0 = identical sequence
```

The strongest historical similarity is used as the comparison evidence.

The current threshold is:

```text
SUBJECT_SIMILARITY_THRESHOLD = 0.50
```

If the strongest historical similarity is below 0.50, the subject can be considered anomalous.

**Example:**

```text
Historical subjects:
  quarterly supplier review
  supplier review update
  supplier contract review
Current subject:
  urgent payment instruction
Similarity:
  Below established threshold
Indicator:
  - Message subject differs substantially from historical message patterns
```

### Body Normalization

Before body comparison, BEC-008 normalizes the current and historical message bodies.

Normalization includes:

1. Converting content to lowercase.
2. Collapsing repeated whitespace.
3. Removing unnecessary surrounding whitespace.

**For example:**

```text
Original:
  Hello Team,
  Please review the attached supplier invoice.
Normalized:
  hello team, please review the attached supplier invoice.
```

The current implementation uses normalized textual content and does not perform semantic NLP or embedding-based comparison.

### Body Similarity

BEC-008 compares the normalized current body against normalized historical bodies using `difflib.SequenceMatcher`.

The strongest historical similarity is used as the comparison evidence.

The current threshold is:

```text
BODY_SIMILARITY_THRESHOLD = 0.50
```

If the strongest historical similarity is below 0.50, the body can be considered anomalous.

**Example:**

```text
Historical message pattern:
  Please review the supplier invoice and confirm the
  expected payment date.
Current message:
  Please urgently change the beneficiary account and
  process the payment immediately.
Similarity:
  Below established threshold
Indicator:
  - Message body differs substantially from historical message patterns
```

### Body Length Analysis

BEC-008 compares the current normalized body length against historical body lengths.

The historical baseline uses the median body length.

The current body is considered anomalous when its length is:

- Greater than two times the historical median, or
- Less than one-half of the historical median.

The current threshold is:

```text
BODY_LENGTH_RATIO_THRESHOLD = 2.0
```

**For example:**

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

Exact threshold boundaries are treated as normal.

### Zero-Length Historical Bodies

BEC-008 handles a zero historical median explicitly.

When:

```text
Historical median:
  0
```

a non-zero current body length can be considered anomalous.

This prevents a division-by-zero condition during ratio analysis.

A current empty body remains consistent with a zero-length historical baseline.

### Attachment Filename Normalization

BEC-008 normalizes attachment filenames before historical comparison.

This allows attachment filename novelty to be evaluated consistently.

Invalid or empty attachment filenames are ignored.

Attachment entries that do not contain usable filename information do not automatically become suspicious.

### Attachment Filename Novelty

BEC-008 compares current attachment filenames against filenames observed in qualifying historical observations.

The analysis requires at least three historical observations containing attachment metadata before the historical attachment filename baseline is established.

**For example:**

```text
Historical attachments:
invoice.pdf
invoice.pdf
invoice.pdf
Current attachment:
invoice-final.pdf
```

The current filename has not previously appeared in the established historical attachment filename baseline.

The rule can therefore produce:

```text
Indicator:
  - Message contains a novel attachment filename
```

The analysis preserves the distinction between a known historical attachment filename and a previously unseen attachment filename.

#### Invalid Attachment Metadata

Invalid attachment metadata is ignored during filename novelty analysis.

Examples include:

- Non-dictionary attachment entries
- Empty filenames
- Invalid filenames
- Historical observations without a usable attachment list
- Historical attachment entries without a valid filename

This prevents malformed historical data from being interpreted as a genuine attachment anomaly.

#### Attachment Filename Baseline

The attachment filename baseline is established independently from subject and body baselines.

**For example:**

```text
Subject history:
  Sufficient
Body history:
  Sufficient
Attachment history:
  Insufficient
```

In this situation:

- Subject analysis can proceed.
- Body analysis can proceed.
- Attachment filename novelty analysis remains unavailable.

This signal-specific baseline behavior is an important part of the methodology.

### Attachment Size Analysis

BEC-008 evaluates attachment sizes against historical attachment-size baselines.

Attachment size analysis is performed per normalized attachment filename.

**For example:**

```text
Historical:
invoice.pdf:
  100 KB
  110 KB
  105 KB
```

The historical median is:

```text
105 KB
```

A current `invoice.pdf` attachment is evaluated against that filename-specific baseline.

### Attachment Size Historical Requirement

Attachment size analysis requires at least three valid historical size observations for the same normalized filename.

**For example:**

```text
invoice.pdf:
  100 KB
  110 KB
  105 KB
```

provides a sufficient historical baseline. However:

```text
invoice.pdf:
  100 KB
  110 KB
```

does not provide sufficient historical observations for the attachment-size signal.

Insufficient history does not itself produce an anomaly.

### Attachment Size Anomaly Threshold

The current attachment size is considered anomalous when it is:

- Greater than 2.0 × the historical median, or
- Less than 0.5 × the historical median.

The current threshold is:

```text
BODY_LENGTH_RATIO_THRESHOLD = 2.0
```

For attachment-size analysis, the same configured ratio threshold is used to determine the upper and lower size boundaries.

**For example:**

```text
Historical sizes:
  100 KB
  100 KB
  100 KB
Historical median:
  100 KB
Upper boundary:
  200 KB
Lower boundary:
  50 KB
```

A current size of `201 KB` is anomalous. A current size of `49 KB` is anomalous.

Exact boundary values are treated as normal:

```text
200 KB → normal
50 KB  → normal
```

### Zero Historical Attachment Size

BEC-008 explicitly handles a zero historical attachment-size median.

When:

```text
Historical median:
  0
```

a non-zero current attachment size can be considered anomalous.

This prevents a division-by-zero condition during ratio analysis.

A current zero-size attachment remains consistent with a zero historical median.

### Invalid Attachment Sizes

Invalid attachment sizes are ignored during historical attachment-size analysis.

Examples include:

- Non-dictionary attachment entries
- Invalid filenames
- Boolean size values
- Non-numeric size values
- Missing size values

Invalid current attachment metadata is also ignored rather than automatically being treated as anomalous.

This ensures that malformed metadata does not produce a false positive simply because it cannot participate in the baseline comparison.

### Filename-Specific Attachment Baselines

Attachment-size analysis is performed per normalized filename.

This prevents unrelated attachment types from being combined into a single historical baseline.

**For example:**

```text
Historical:
invoice.pdf:
  100 KB
  105 KB
  110 KB
contract.pdf:
  900 KB
  950 KB
  1000 KB
```

A current `invoice.pdf` attachment is compared against the `invoice.pdf` baseline rather than against the combined size distribution of all attachments.

This makes the size comparison more specific to the established historical attachment pattern.

### Multiple Attachment Signals

BEC-008 evaluates attachment filename novelty and attachment size independently.

A message can therefore produce multiple attachment-related indicators.

**For example:**

```text
Historical:
invoice.pdf:
  100 KB
  100 KB
  100 KB
Current:
invoice-final.pdf:
  500 KB
```

**Potential indicators include:**

- Message contains a novel attachment filename
- Attachment size differs substantially from the historical attachment-size baseline

The individual signals remain explainable and can be represented in the structured detection evidence.

### Multiple Content and Attachment Anomalies

BEC-008 evaluates all applicable signals independently.

A single message can therefore produce several indicators:

```text
Current message:
Subject:
  URGENT PAYMENT CHANGE
Body:
  Long, substantially different message content
Attachment:
  invoice-final.pdf
  500 KB

Historical baseline:
Subject:
  Quarterly supplier review
Body:
  Short, recurring supplier-review message
Attachment:
  invoice.pdf
  100 KB
```

**Potential indicators:**

- Message subject differs substantially from historical message patterns
- Message body differs substantially from historical message patterns
- Message body length differs substantially from historical message patterns
- Message contains a novel attachment filename
- Attachment size differs substantially from the historical attachment-size baseline

This allows BEC-008 to preserve multiple independent pieces of content evidence rather than reducing the analysis to a single generic content score.

### Signal-Specific Historical Requirements

BEC-008 uses signal-specific historical requirements.

| Signal | Minimum requirement |
|---|---|
| Subject similarity | 3 valid historical observations |
| Body similarity | 3 valid historical observations |
| Body length | 3 valid historical observations |
| Attachment filename novelty | 3 historical observations containing attachment metadata |
| Attachment size anomaly | 3 valid sizes for the same normalized filename |

This prevents a single historical email from being treated as a reliable representation of the sender's normal content or attachment behavior.

It also means that one unavailable signal does not prevent other signals from being evaluated.

### Structured Content and Attachment Evidence

BEC-008 preserves structured evidence for the signals that contribute to a detection.

**Evidence can include:**

**Subject evidence**
- Signal type
- Current normalized subject
- Historical comparison
- Similarity value
- Similarity threshold

**Body evidence**
- Signal type
- Current normalized body
- Historical comparison
- Similarity value
- Similarity threshold

**Body length evidence**
- Current body length
- Historical body lengths
- Historical median
- Ratio threshold

**Attachment filename evidence**
- Current normalized attachment filenames
- Historical attachment filenames
- Novel attachment filenames
- Historical observation count
- Baseline availability

**Attachment size evidence**
- Attachment filename
- Current attachment size
- Historical sizes
- Historical median
- Upper threshold
- Lower threshold
- Baseline availability

This evidence can be preserved by the persistence layer and passed through the SIEM integration.

### Content and Attachment Baseline Independence

BEC-008 treats each historical signal independently.

**For example:**

```text
Subject history:
  5 valid observations
Body history:
  5 valid observations
Attachment filename history:
  2 qualifying observations
Attachment size history:
  3 valid observations
```

The resulting analysis can be:

```text
Subject similarity:
  Available
Body similarity:
  Available
Body length:
  Available
Attachment filename novelty:
  Insufficient historical attachment metadata
Attachment size:
  Available
```

This prevents missing historical data for one signal from disabling unrelated detection signals.

### Current BEC-008 Scope

The currently implemented BEC-008 signals are:

| Signal | Method | Status |
|---|---|---|
| Subject similarity anomaly | SequenceMatcher comparison | Implemented |
| Body similarity anomaly | SequenceMatcher comparison | Implemented |
| Body length anomaly | Median-based ratio | Implemented |
| Attachment filename novelty | Historical normalized filename comparison | Implemented |
| Attachment size anomaly | Filename-specific median-based ratio | Implemented |

BEC-008 is therefore operational within this deterministic scope.

**The rule does not currently perform:**

- Semantic NLP
- Embedding-based similarity
- LLM classification
- Attachment content inspection
- Malware analysis
- Hash reputation analysis
- Archive inspection

These capabilities are outside the current BEC-008 methodology.

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

A conversation-hijacking investigation may therefore combine evidence from multiple rules rather than requiring a single rule to establish compromise.

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

**For example:**

```text
Rule:
  BEC-008 — Message Content Anomaly
Severity:
  MEDIUM
Matched:
  true
Indicators:
  - Message subject differs substantially from historical message patterns
  - Message contains a novel attachment filename
```

BEC-007 and BEC-008 can also expose structured evidence objects containing the underlying comparison values and historical baseline information.

---

## Explainability

The detection methodology prioritizes explainable evidence.

**Less useful:**

```text
Risk = 85
```

**More useful:**

```text
Rule:
  BEC-001 — Lookalike Domain
Known domain:
  supplier.com
Observed domain:
  supp1ier.com
Indicators:
  - Domain mismatch
  - High domain similarity
```

A behavioral detection can expose its historical evidence:

```text
Rule:
  BEC-007 — Behavioral Communication Anomaly
Historical hours:
  09:00
  10:00
  14:00
Historical range:
  09:00–14:00
Observed hour:
  03:00
Indicator:
  - Message sent outside historically observed communication hours
```

A content detection can expose comparison evidence:

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

An attachment detection can expose its baseline:

```text
Rule:
  BEC-008 — Message Content Anomaly
Signal:
  Attachment size
Filename:
  invoice.pdf
Historical sizes:
  100 KB
  100 KB
  100 KB
Historical median:
  100 KB
Current size:
  250 KB
Upper threshold:
  200 KB
Indicator:
  - Attachment size differs substantially from the historical attachment-size baseline
```

This approach allows a SOC analyst to investigate the underlying evidence rather than relying only on a risk score.

---

## Risk Scoring Methodology

Risk scores are generated from observable indicators associated with individual detection rules.

The score is intended to communicate the relative contribution of a detection to the overall analysis.

Each individual detection score is capped at 100.

The combined analysis risk score is calculated from matched detections.

BEC-007 and BEC-008 can contribute to the overall risk score when their respective behavioral or content signals match.

> Risk scoring should not be treated as a standalone verdict.

Analysts should inspect:

- Matched rules
- Indicators
- Authentication results
- Infrastructure information
- Sender identity
- Conversation context
- Behavioral evidence
- Message content evidence
- Attachment evidence

---

## False Positives

Some legitimate email messages can trigger individual indicators.

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
- Legitimate changes in attachment filenames
- Legitimate changes in attachment sizes
- New legitimate attachment types

For this reason, detections should be interpreted using the complete analysis context.

> Historical behavioral, content, and attachment anomalies are investigation indicators rather than proof of compromise.

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
- The attacker deliberately reproduces established communication patterns
- Malicious attachments closely resemble legitimate historical attachments
- Attachment metadata is unavailable or incomplete

The system therefore treats detection as an investigation aid rather than a guarantee of malicious activity.

---

## Detection Methodology Principles

The current methodology follows several principles.

**Deterministic First**
The project prioritizes deterministic detection rules before introducing statistical or machine-learning-based analysis. This provides predictable behavior, straightforward testing, and explainable results.

**Evidence First**
A detection should preserve the evidence that caused it to match. This is particularly important for behavioral and historical content analysis.

**Historical Baseline Awareness**
Historical observations are only used when sufficient qualifying data exists. A lack of historical data should not automatically be interpreted as suspicious.

**Signal-Specific Baselines**
Different signals require different forms of historical evidence. For example:

```text
Subject similarity:
  Requires valid historical subjects.
Attachment filename novelty:
  Requires historical attachment metadata.
Attachment size:
  Requires valid historical sizes for the same filename.
```

This prevents unrelated historical data from being incorrectly reused across detection signals.

**Invalid Data Handling**
Invalid or unusable metadata is ignored where appropriate. Malformed input should not automatically become a malicious indicator merely because it cannot participate in a baseline comparison.

**Database Independence**
Detection rules do not directly query PostgreSQL. Historical observations are retrieved by the application layer and passed into the detection engine. This keeps the rules:

- Testable
- Deterministic
- Decoupled from persistence
- Easier to extend

**Analyst-Centered Detection**
Detection results are intended to support SOC investigation. The system provides evidence and context rather than attempting to replace analyst judgment.

---

## Future Methodology

Future development may introduce statistical and machine-learning-based behavioral detection.

**Potential models include:**

- Isolation Forest
- Local Outlier Factor
- One-Class SVM
- Autoencoder-based anomaly detection

The ML layer will remain separate from the deterministic detection engine so that rule-based and statistical approaches can be evaluated independently.

**Potential future content-analysis capabilities may include:**

- Semantic similarity
- Embedding-based message comparison
- Communication-template analysis
- Topic or intent deviation
- Language-pattern analysis

**Potential future attachment-analysis capabilities may include:**

- Attachment type analysis
- Hash-based comparison
- Attachment frequency analysis
- Attachment content analysis
- Malware analysis
- Archive inspection
- Reputation enrichment

These capabilities are not currently part of BEC-008.

Future statistical or machine-learning detection should build on clearly defined observation sources, sufficient historical data, measurable baselines, and explainable evidence.

---

## Current Methodology Summary

The current detection methodology can be summarized as:

```text
                Incoming Email
                      │
                      ▼
              Parse & Normalize
                      │
                      ▼
             Establish Context
                      │
          ┌───────────┼───────────┐
          │           │           │
          ▼           ▼           ▼
       Identity   Authentication Infrastructure
          │           │           │
          └───────────┼───────────┘
                      │
                      ▼
               Conversation
                  Analysis
                      │
                      ▼
             Historical Context
                      │
              ┌───────┴────────┐
              │                │
              ▼                ▼
          BEC-007          BEC-008
        Behavioral      Content & Attachment
          Analysis           Analysis
              │                │
              └───────┬────────┘
                      │
                      ▼
              Detection Results
                      │
                      ▼
                Risk Scoring
                      │
              ┌───────┴───────┐
              ▼               ▼
         Persistence       Optional SIEM
```

The methodology is intentionally deterministic, baseline-aware, evidence-first, and extensible. It establishes an explainable foundation for future statistical and machine-learning-based detection without making the current system dependent on opaque models.
