# Detection Methodology

## Overview

Email Conversation Integrity Detection uses a layered and explainable detection methodology.

The system compares an analyzed email against a supplied baseline representing known sender identity, participants, infrastructure, and communication behavior. Where historical sender observations are available, the system can also compare the current message against previously observed communication behavior.

The objective is to identify inconsistencies that may indicate Business Email Compromise (BEC), impersonation, conversation hijacking, or abnormal communication behavior.

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

The baseline should represent legitimate communication patterns as accurately as possible.

Where persisted historical observations are available, they provide an additional evidence source for behavioral analysis.

> Poor or incomplete baseline information can produce false positives or reduce the amount of behavioral evidence available to the detection engine.

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
Observed:            alice@company.com, bob@supplier.com, attacker@example.net
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

BEC-007 evaluates whether a message's communication timing differs from an established sender or conversation baseline.

The current implementation uses deterministic temporal behavioral analysis based on:

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

BEC-007 extracts the local sending hour from each valid historical timestamp.

A minimum of three valid historical observations is required before a historical sending-hour range is established.

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

Historical observations with missing or invalid timestamps are ignored.

> The historical range represents observed message timestamps available to the system. It is not a guarantee that the sender always communicates within that range.

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

The historical observation data passed to BEC-007 includes the persisted `email_sent_at` value.

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

Historical observations can provide an additional indicator:

```text
Historical range:
  09:00–14:00
Observed:
  02:30
Indicator:
  - Message sent outside historically observed communication hours
```

The indicators are independently evaluated and returned together when multiple behavioral conditions are violated.

### Behavioral Baselines

All explicit behavioral baselines are optional.

- If `typical_hours` is supplied, the observed sending hour is evaluated.
- If `typical_days` is supplied, the observed weekday is evaluated.
- If `typical_timezone_offsets` is supplied, the observed `Date` header timezone offset is evaluated.
- If sufficient historical sender observations are available, the historical sending-hour range is evaluated.
- An empty explicit behavioral baseline does not independently produce a behavioral detection.
- Historical analysis is only performed when sufficient valid historical observations are available.

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

These signals are intentionally deterministic and explainable.

### Future Behavioral Analysis

Future behavioral analysis may include:

- Sender frequency
- Recipient frequency
- Response time
- Participant count
- Subject similarity
- Body similarity
- Attachment frequency
- Infrastructure frequency
- Domain similarity
- Reply-To frequency

These signals are not currently implemented by BEC-007.

> Future behavioral signals should only be introduced when the system has a clearly defined observation source, sufficient data, and a clearly defined baseline or statistical methodology for that signal.

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

---

## Risk Scoring Methodology

Risk scores are generated from observable indicators associated with individual detection rules.

The score is intended to communicate the relative contribution of a detection to the overall analysis.

Each individual detection score is capped at 100. The combined analysis risk score is calculated from matched detections.

> The score should not be treated as a standalone verdict.

Analysts should inspect:

- Matched rules
- Indicators
- Authentication results
- Infrastructure information
- Sender identity
- Conversation context
- Behavioral evidence

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

For this reason, detections should be interpreted using the complete analysis context.

Historical behavioral anomalies should be treated as investigation indicators rather than proof of compromise.

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
