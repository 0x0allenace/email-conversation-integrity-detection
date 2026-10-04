# Detection Methodology

## Overview

Email Conversation Integrity Detection uses a layered and explainable detection methodology.

The system compares an analyzed email against a supplied baseline representing known sender identity, participants, infrastructure, and communication behavior. Where historical sender observations are available, the system can also compare the current message against previously observed communication behavior and historical message content.

The objective is to identify inconsistencies that may indicate Business Email Compromise (BEC), impersonation, conversation hijacking, abnormal communication behavior, or suspicious changes in message content.

The methodology prioritizes deterministic, explainable detection rules before statistical or machine-learning-based anomaly detection.

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
       Behavior Analysis
              │
              ├── Supplied Behavioral Baseline
              │
              └── Historical Sender Observations
              │
              ▼
       Message Content Analysis
              │
              ├── Historical Subject Patterns
              │
              ├── Historical Body Patterns
              │
              └── Historical Body Length
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

Historical observations can provide additional evidence for behavioral and message-content analysis.

The baseline should represent legitimate communication patterns as accurately as possible.

Where persisted historical observations are available, they provide an additional evidence source for behavioral and content analysis.

> Poor or incomplete baseline information can produce false positives or reduce the amount of behavioral and content evidence available to the detection engine.

---

## Identity Analysis

Identity analysis examines the relationship between the observed sender and the known sender identity.

Relevant fields include:

- Email address
- Domain
- Display name

The analysis looks for inconsistencies such as:

```text
Known:    john@supplier.com
Observed: john@supp1ier.com
```

A matching display name does not establish that the underlying sender identity is legitimate.

---

## Domain Similarity

Lookalike-domain detection compares the observed sender domain with the trusted domain.

```text
Trusted:  supplier.com
Observed: supp1ier.com
```

The purpose is to identify visually similar domains that could be used for impersonation.

The current implementation uses deterministic domain similarity logic.

---

## Reply-To Analysis

The Reply-To address is compared with the apparent sender identity.

```text
From:     John Smith <john@supplier.com>
Reply-To: john.supplier@gmail.com
```

A mismatch can indicate that replies may be redirected away from the apparent sender.

The mismatch is treated as an indicator rather than automatic proof of malicious activity.

---

## Participant Analysis

The system compares observed conversation participants with the supplied participant baseline.

```text
Known participants: alice@company.com, bob@supplier.com
Observed:           alice@company.com, bob@supplier.com, attacker@example.net
```

The additional participant can become a detection indicator.

The baseline should include all legitimate participants expected within the conversation.

---

## Authentication Analysis

The system extracts and evaluates available authentication information.

Current authentication signals include:

- SPF
- DKIM
- DMARC

Authentication results provide supporting evidence for detection rules.

> Authentication failure alone does not necessarily establish that a message is malicious, because legitimate email infrastructure can produce authentication anomalies.

---

## Infrastructure Analysis

Infrastructure analysis compares observed sender infrastructure against known infrastructure.

**Current indicators include:**

- Sending host
- Sending IP address

```text
Known host:    mail.supplier.com
Observed host: new-mail.example.net
```

A previously unseen host or IP address can increase suspicion when combined with other indicators.

---

## BEC-007 — Behavioral Communication Anomaly

BEC-007 evaluates whether a message's communication behavior differs from an established sender or conversation baseline.

The current implementation uses deterministic behavioral analysis based on:

- Explicitly supplied behavioral baselines
- Historical sender observations when available

The rule does not require machine learning.

Historical observations are retrieved by the application service from persisted analysis records and passed into the detection engine as structured data. BEC-007 itself remains independent of the database.

### Email Timestamp

The original email `Date` header is parsed during analysis and preserved as `email_sent_at` in the persisted analysis record.

This timestamp is distinct from `analyzed_at`:

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

### Day of Week

The optional `typical_days` baseline defines the expected communication days. Python weekday numbering is used:

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

BEC-007 extracts the local sending hour from each valid historical timestamp. A minimum of three valid historical observations is required before historical behavioral analysis is established.

Historical observations can provide evidence for multiple behavioral signals, including:

- Historical sending-hour range
- Sending frequency
- Recipient frequency
- Recipient co-occurrence
- Recipient role relationships

Historical observations with missing or invalid data for a specific signal are ignored for that signal.

### Historical Sending-Hour Range

A minimum of three valid historical observations is required before a historical sending-hour range is established.

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

**For example:**

```text
Historical sending hours:
  09:00
  10:00
  14:00
Historical range:
  09:00–14:00
Current message:
  03:30
Indicator:
  - Message sent outside historically observed communication hours
```

The historical range is calculated from the minimum and maximum valid observed sending hours.

> The historical range represents observed message timestamps available to the system. It is not a guarantee that the sender always communicates within that range.

### Historical Sending Frequency

BEC-007 can compare the current sending interval against the sender's historically observed communication cadence.

Historical observations are ordered by their persisted `email_sent_at` timestamps. Valid consecutive observations are used to establish the sender's historical sending intervals.

A minimum of three historical observations is required before frequency-based behavioral analysis is established.

The current message is compared against the established historical communication cadence. The detection uses a deterministic frequency comparison rather than machine learning.

The result can expose structured evidence describing the observed and historical communication frequency.

This signal is intended to identify substantial deviations from an established sending cadence, such as a message being sent considerably sooner than historically observed communication intervals.

> Sending frequency is an observed behavioral signal. A change in communication cadence can be legitimate and should be evaluated alongside the other detection evidence.

### Historical Recipient Behavior

BEC-007 evaluates whether the current message is addressed to recipients that have not previously appeared in the sender's established communication history.

The current recipient set is derived from the message's `To` and `Cc` fields. Historical recipients are recovered from persisted sender analyses, using the recipient data stored in each historical analysis result.

Recipient values are normalized before comparison by:

1. Removing surrounding whitespace.
2. Converting addresses to lowercase.
3. Removing duplicate addresses.
4. Ignoring non-string recipient values.

A minimum of three qualifying historical observations is required before recipient history is used as a behavioral baseline. Historical observations without usable `To` or `Cc` recipient data do not count toward this threshold.

When a current recipient is absent from the established historical recipient set, BEC-007 records:

```text
Message sent to a previously unseen recipient
```

The detection result also exposes:

- `historical_recipients` — recipients observed across the qualifying historical sender observations.
- `unusual_recipients` — current recipients that were not observed in the historical baseline.

> This signal is a behavioral anomaly indicator rather than proof of malicious activity. A previously unseen recipient can be legitimate, for example when a sender begins communicating with a new customer, colleague, supplier, or business partner. The signal is therefore intended to be evaluated alongside the other BEC-007 behavioral indicators and the project's other deterministic detection rules.

The historical recipient baseline is derived from persisted analysis results rather than requiring a separate recipient-history database table or schema migration.

### Historical Recipient Frequency

BEC-007 can also evaluate how frequently individual recipients have historically appeared in the sender's communication.

Recipient frequency is calculated from qualifying historical observations containing usable `To` or `Cc` recipient data. The historical frequency represents the proportion of qualifying observations in which a recipient appeared.

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

When the current message includes a historically known recipient whose historical frequency is unusually low, BEC-007 can record that relationship as behavioral evidence.

Recipient frequency is evaluated separately from the unseen-recipient signal:

```text
Unseen recipient:
  Recipient has never appeared historically.
Low-frequency recipient:
  Recipient is known historically but appears substantially less often.
```

This distinction allows the detection engine to preserve more granular behavioral evidence.

> A low-frequency recipient is not inherently suspicious. New projects, escalations, one-off business interactions, and legitimate changes in communication patterns can produce low historical frequencies.

### Historical Recipient Co-Occurrence

BEC-007 evaluates whether recipients who appear together in the current message have historically appeared together in the sender's communication history.

The current recipient set combines normalized `To` and `Cc` recipients.

Historical recipient pairs are generated from each qualifying historical observation. Recipient pairs are treated as unordered relationships, meaning:

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

The analysis only treats recipients as historically established when they have appeared in the sender's qualifying historical observations.

This allows recipient co-occurrence analysis to distinguish between:

- A recipient that has never appeared before.
- A known recipient appearing in an established relationship.
- Known recipients appearing together in a historically unusual combination.

> Recipient co-occurrence is an observed communication-pattern signal. Legitimate business events can create new recipient relationships.

### Historical Recipient Role Anomaly

BEC-007 also evaluates whether established recipient pairs normally occupy the same `To` and `Cc` roles.

Recipient role analysis builds on the historical co-occurrence relationship. It is only applied when the recipient pair is already an established relationship.

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

the same recipients are present and their relationship is known, but their historical communication roles have changed. BEC-007 can record:

```text
Message contains a historically unusual recipient role relationship
```

Recipient roles are derived from the current `To` and `Cc` fields.

If a recipient appears in both `To` and `Cc`, the `To` role takes precedence so that each recipient has one deterministic role for analysis. Multiple recipients are supported in both fields.

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

A minimum of three qualifying historical observations is required before recipient role analysis is established.

> An unseen recipient pair is handled by recipient co-occurrence analysis rather than being treated as a recipient role anomaly.

> A change in recipient role is an observed communication-pattern anomaly. Legitimate workflow changes can cause recipients to move between `To` and `Cc`.

### Historical Behavioral Evidence

BEC-007 can therefore evaluate several dimensions of historical communication behavior:

```text
Historical Sender Behavior
        │
        ├── Sending-hour range
        ├── Sending frequency
        │
        └── Recipient behavior
              │
              ├── Recipient presence
              ├── Recipient frequency
              ├── Recipient co-occurrence
              └── Recipient role relationship
```

These signals are evaluated independently so that multiple behavioral inconsistencies can be reported for the same message.

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

The historical observation data passed to BEC-007 includes the persisted `email_sent_at` value and previously analyzed email recipient information.

### Multiple Behavioral Anomalies

BEC-007 can report multiple behavioral inconsistencies for the same message.

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

Historical observations can provide additional indicators:

```text
Historical range:
  09:00–14:00
Observed:
  02:30
Indicator:
  - Message sent outside historically observed communication hours
```

Recipient behavior can provide additional indicators:

```text
Historical:
  alice@example.com + finance@example.com
Observed:
  alice@example.com + legal@example.com
Indicators:
  - Message contains a historically unusual recipient relationship
```

A role anomaly can provide additional evidence:

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

### Behavioral Baselines

All explicit behavioral baselines are optional.

- If `typical_hours` is supplied, the observed sending hour is evaluated.
- If `typical_days` is supplied, the observed weekday is evaluated.
- If `typical_timezone_offsets` is supplied, the observed `Date` header timezone offset is evaluated.
- If sufficient historical sender observations are available, the historical sending-hour range is evaluated.
- If sufficient historical observations contain usable timestamps, historical sending frequency is evaluated.
- If sufficient historical observations contain usable recipient data, historical recipient behavior is evaluated.
- An empty explicit behavioral baseline does not independently produce a behavioral detection.
- Historical analysis is only performed when sufficient valid historical observations are available for the relevant signal.

This allows existing clients to provide only the behavioral information they currently maintain while supporting richer behavioral evidence as the system evolves.

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

The persisted analysis record also preserves `email_sent_at`, allowing the original message timestamp to remain available for historical analysis.

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

### Future Behavioral Analysis

Future behavioral analysis may include:

- Response time
- Participant count
- Attachment frequency
- Infrastructure frequency
- Domain similarity
- Reply-To frequency
- Other statistically derived behavioral features

These signals are not currently implemented by BEC-007.

> Subject similarity and body similarity are implemented separately by BEC-008 and are therefore not part of the future BEC-007 behavioral scope.

> Future behavioral signals should only be introduced when the system has a clearly defined observation source, sufficient data, and a clearly defined baseline or statistical methodology for that signal.

---

## BEC-008 — Message Content Anomaly

BEC-008 evaluates whether the content of a current message differs substantially from the sender's established historical message-content patterns.

The rule focuses on deterministic comparison of:

- Subject similarity
- Body similarity
- Body length

BEC-008 uses historical message observations supplied by the application layer. The rule does not directly access the database and does not require machine learning or external natural-language-processing services.

The purpose is to identify substantial changes in message content that may provide supporting evidence of conversation manipulation, impersonation, or other suspicious communication activity.

> BEC-008 is a content anomaly detector, not a semantic classifier. A content difference does not establish malicious intent by itself.

### Historical Content Baseline

Historical message observations are retrieved by the application service and passed to the detection engine as structured data.

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
BEC-008
```

The detection rule remains independent of direct database access.

A minimum of three valid historical observations is required before BEC-008 performs historical content analysis.

Historical observations must contain usable subject or body content for the corresponding signal to participate in that signal's analysis. This means:

- Subject analysis requires at least three valid historical subjects.
- Body similarity analysis requires at least three valid historical bodies.
- Body-length analysis requires at least three valid historical body lengths.

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

The resulting similarity value is represented between:

```text
0.0 = no meaningful sequence similarity
1.0 = identical sequence
```

The current subject is compared against the available historical subjects and the strongest historical similarity is used as the comparison evidence.

The current subject similarity threshold is:

```text
0.50
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

The threshold is deterministic and currently configured as:

```text
SUBJECT_SIMILARITY_THRESHOLD = 0.50
```

### Body Normalization

Before body comparison, BEC-008 normalizes the current and historical message bodies.

Normalization includes:

1. Converting content to lowercase.
2. Collapsing repeated whitespace.
3. Removing unnecessary surrounding whitespace.

The current implementation focuses on normalized textual content. It does not perform:

- Semantic NLP
- Embedding-based similarity
- External AI classification
- Attachment analysis
- Malware analysis

**For example:**

```text
Original:
  Hello Team,
  Please review the attached supplier invoice.
Normalized:
  hello team, please review the attached supplier invoice.
```

### Body Similarity

BEC-008 compares the normalized current body against normalized historical message bodies.

The comparison uses Python's standard-library `difflib.SequenceMatcher`.

The strongest historical similarity is used as the comparison evidence.

The current body similarity threshold is:

```text
0.50
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

The threshold is deterministic and currently configured as:

```text
BODY_SIMILARITY_THRESHOLD = 0.50
```

### Body Length Analysis

BEC-008 also compares the current body length against the historical body-length baseline.

Historical body lengths are calculated from the normalized body content.

The historical baseline uses the median body length.

The current implementation considers the current body anomalous when its length is:

- Greater than two times the historical median, or
- Less than one-half of the historical median.

The current threshold is:

```text
BODY_LENGTH_RATIO_THRESHOLD = 2.0
```

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

A current body length of:

```text
1200
```

would therefore produce a body-length anomaly because it exceeds twice the historical median.

Similarly, a current body length of:

```text
150
```

would produce an anomaly because it is less than half the historical median.

### Zero-Length Historical Bodies

BEC-008 handles a zero historical median explicitly.

When the historical median body length is zero:

```text
Historical median:
  0
```

a current body with content can be considered anomalous. This prevents the ratio comparison from attempting to divide by zero.

A current empty body remains consistent with a zero-length historical baseline.

### Multiple Content Anomalies

BEC-008 evaluates subject, body similarity, and body length independently.

A single message can therefore produce multiple content indicators.

**For example:**

```text
Historical message pattern:
Subject:
  Quarterly supplier review
Body:
  Please review the supplier invoice and confirm
  the expected payment date.
Current message:
Subject:
  URGENT PAYMENT CHANGE
Body:
  Please immediately update the beneficiary account
  and process the outstanding payment today.
  This request requires urgent handling because
  the normal payment process has changed.
Indicators:
  - Message subject differs substantially from historical message patterns
  - Message body differs substantially from historical message patterns
  - Message body length differs substantially from historical message patterns
```

Each signal is evaluated independently so that the resulting detection preserves the evidence that contributed to the anomaly.

### Structured Content Evidence

BEC-008 exposes structured evidence rather than relying only on a plain-text indicator.

The structured evidence can identify:

- Signal type
- Current normalized subject
- Historical subject comparison
- Subject similarity
- Subject similarity threshold
- Current normalized body
- Historical body comparison
- Body similarity
- Body similarity threshold
- Current body length
- Historical body lengths
- Historical median body length
- Body-length threshold
- Historical observation count

This allows downstream components such as the API, persistence layer, and SIEM integration to preserve more detailed investigation evidence.

A conceptual example is:

```text
Rule:
  BEC-008 — Message Content Anomaly
Signal:
  subject_similarity
Evidence:
  Current subject:
    urgent payment instruction
  Best historical similarity:
    0.31
  Threshold:
    0.50
Indicator:
  Message subject differs substantially from historical message patterns
```

Another signal may expose:

```text
Signal:
  body_length
Evidence:
  Current body length:
    1200
  Historical median:
    450
  Threshold:
    2.0x
Indicator:
  Message body length differs substantially from historical message patterns
```

The exact structured evidence returned by the implementation may contain additional fields as the detection model evolves.

### Content Baseline Requirements

BEC-008 requires sufficient historical observations before performing content analysis.

The current minimum is:

```text
MIN_HISTORICAL_OBSERVATIONS = 3
```

This minimum is applied independently to the available content signals.

**For example:**

```text
Historical observations:
  2
Result:
  Insufficient historical content baseline
```

No historical content anomaly should be inferred from fewer than the required minimum observations.

With sufficient historical observations:

```text
Historical observations:
  3+
Result:
  Historical content comparison available
```

This prevents a single previous message from being treated as a reliable representation of a sender's established communication style.

### Historical Content Observation Source

Historical content observations are supplied by the application layer.

The detection rule does not query PostgreSQL directly.

This separation follows the same architecture used by BEC-007:

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

This keeps the detection rule deterministic, testable, and independent of persistence implementation details.

### Attachments

Attachment analysis is currently outside the scope of BEC-008.

The current rule does not evaluate:

- Attachment names
- Attachment types
- Attachment hashes
- Attachment frequency
- Attachment content
- Malware indicators
- Archive contents

Attachment-based analysis may be introduced as a separate detection capability in the future.

### Current Content Scope

The currently implemented BEC-008 content signals are:

| Signal | Source | Status |
|---|---|---|
| Subject similarity anomaly | Historical message observations | Implemented |
| Body similarity anomaly | Historical message observations | Implemented |
| Body length anomaly | Historical message observations | Implemented |
| Attachment analysis | Historical message observations | Out of scope |

These signals are intentionally deterministic and explainable.

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

This structure allows analysts to understand which detection rule matched and why.

For BEC-007 and BEC-008, Indicators may contain both human-readable strings and structured evidence objects.

**For example:**

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

---

## Risk Scoring Methodology

Risk scores are generated from observable indicators associated with individual detection rules.

The score is intended to communicate the relative contribution of a detection to the overall analysis.

Each individual detection score is capped at 100. The combined analysis risk score is calculated from matched detections.

BEC-008 contributes to the risk score when the rule matches and a content anomaly is identified.

> The score should not be treated as a standalone verdict.

Analysts should inspect:

- Matched rules
- Indicators
- Authentication results
- Infrastructure information
- Sender identity
- Conversation context
- Behavioral evidence
- Message content evidence

---

## Explainability

The detection methodology prioritizes explainable evidence.

**Bad:**

```text
Risk = 85
```

**Good:**

```text
Rule:            BEC-001 — Lookalike Domain
Known domain:    supplier.com
Observed domain: supp1ier.com
Indicators:
- Domain mismatch
- High domain similarity
```

A behavioral detection can similarly expose the evidence behind the anomaly:

```text
Rule:              BEC-007 — Behavioral Communication Anomaly
Historical hours:  09:00, 10:00, 14:00
Historical range:  09:00–14:00
Observed hour:     03:00
Indicator:
- Message sent outside historically observed communication hours
```

A content detection can expose the historical comparison evidence:

```text
Rule:                 BEC-008 — Message Content Anomaly
Signal:               Subject similarity
Current subject:     urgent payment instruction
Best historical match:
  quarterly supplier review
Similarity:           0.31
Threshold:            0.50
Indicator:
- Message subject differs substantially from historical message patterns
```

This allows a SOC analyst to investigate the underlying evidence instead of relying only on a risk score.

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
- One-off recipients or low-frequency recipients
- Legitimate changes to message subjects
- Legitimate changes to message body content
- Short or unusually detailed messages
- New business processes that produce different message templates
- Legitimate automated messages with different content patterns

For this reason, detections should be interpreted using the complete analysis context.

Historical behavioral and content anomalies should be treated as investigation indicators rather than proof of compromise.

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
- The attacker deliberately reproduces the sender's established communication patterns

The system therefore treats detection as an investigation aid rather than a guarantee of malicious activity.

---

## Future Methodology

Future development may introduce statistical and machine-learning-based behavioral detection.

Potential models include:

- Isolation Forest
- Local Outlier Factor
- One-Class SVM
- Autoencoder-based anomaly detection

The ML layer will remain separate from the deterministic detection engine so that rule-based and behavioral approaches can be evaluated independently.

Future statistical analysis should build on clearly defined historical observation sources and should not replace the existing explainable detection evidence.

**Potential future content-analysis capabilities may include:**

- Semantic similarity
- Embedding-based message comparison
- Attachment frequency analysis
- Attachment metadata analysis
- Communication-template analysis
- Topic or intent deviation
- Language-pattern analysis

> These capabilities are not currently part of BEC-008 and should only be introduced when their observation source, baseline, methodology, and explainability requirements are clearly defined.
