# Detection Methodology

## 1. Purpose

The Email Clone Detector uses a layered detection methodology to identify messages that may represent impersonation, conversation hijacking, or other forms of Business Email Compromise.

The methodology prioritizes:

- Observable evidence
- Deterministic detection
- Explainability
- Contextual analysis
- Multiple independent indicators

> A single indicator should generally not be treated as sufficient evidence of malicious activity.

---

## 2. Detection Layers

```text
1. Email Parsing
       ↓
2. Header Analysis
       ↓
3. Conversation Analysis
       ↓
4. Identity Analysis
       ↓
5. Authentication Analysis
       ↓
6. Infrastructure Analysis
       ↓
7. Behavioral Analysis
       ↓
8. Detection Correlation
       ↓
9. Risk Scoring
       ↓
10. Alert Generation
```

---

## 3. Email Parsing

The first stage converts the raw email into a normalized representation.

Required fields include:

```text
From
To
Cc
Reply-To
Return-Path
Subject
Date
Message-ID
In-Reply-To
References
Received
Authentication-Results
Body
Attachments
```

The parser must preserve the original values for forensic review.

---

## 4. Header Analysis

Headers provide important evidence about the origin and handling of a message.

The system should identify inconsistencies such as:

- `From` ≠ `Reply-To`
- `From` ≠ `Return-Path`
- Unexpected `Received` chain
- Missing expected threading headers
- Unexpected `Message-ID` structure

> Header anomalies should be evaluated in context. For example, a `Reply-To` address different from `From` is not inherently malicious — legitimate mailing systems and support workflows may use this configuration.

---

## 5. Conversation Reconstruction

A conversation baseline is created from previously observed messages.

The baseline may contain:

- Known participants
- Known domains
- Known subjects
- Known Reply-To addresses
- Known infrastructure
- Known communication patterns
- Known thread identifiers

**Example:**

```text
Conversation #1001
Participants:
  alice@company.com
  bob@supplier.com
  finance@company.com
```

A new message introducing `bob@supp1ier.com` should be compared against the established baseline.

---

## 6. Identity Analysis

Identity analysis evaluates whether the observed sender is consistent with a known participant.

### 6.1 Exact Match

| | Address |
|---|---|
| Known | `bob@supplier.com` |
| Observed | `bob@supplier.com` |

No identity mismatch.

### 6.2 Display Name Match With Address Mismatch

| | Identity |
|---|---|
| Known | `Bob Smith <bob@supplier.com>` |
| Observed | `Bob Smith <attacker@example.com>` |

Potential impersonation indicator.

### 6.3 Lookalike Domain

The system compares the observed domain with known participant domains.

```text
supplier.com
supp1ier.com
```

Potential techniques include:

- Character substitution
- Insertion
- Deletion
- Transposition
- Homoglyph detection
- Edit distance

The result should be treated as an indicator rather than proof of malicious intent.

---

## 7. Reply-To Analysis

The system compares `From`, `Reply-To`, and `Return-Path`.

**Example:**

```text
From:     bob@supplier.com
Reply-To: bob@external-mail.com
```

Potential risk increases when this occurs alongside other anomalies.

---

## 8. Authentication Analysis

The system records available authentication results: SPF, DKIM, DMARC.

**Example:**

```text
SPF:   fail
DKIM:  fail
DMARC: fail
```

Authentication failures should be correlated with identity and infrastructure evidence.

> The detector should avoid simplistic logic such as "DKIM failed = malicious," because legitimate forwarding and email infrastructure can produce authentication anomalies.

---

## 9. Infrastructure Analysis

The system establishes historical infrastructure associated with known senders.

Potential attributes include:

- IP
- Hostname
- ASN
- Reverse DNS
- Mail server
- Geographic region

**Example:**

```text
Known sender infrastructure:
  203.0.113.10
  203.0.113.11
Observed:
  198.51.100.45
```

A previously unseen infrastructure source can increase suspicion when combined with other indicators.

---

## 10. Behavioral Analysis

Behavioral analysis compares the current message with historical communication patterns.

Potential features:

- `sending_hour`
- `sending_day`
- `sender_frequency`
- `recipient_frequency`
- `response_time`
- `participant_count`
- `subject_similarity`
- `attachment_frequency`

**Example:**

```text
Historical sender behavior:  09:00–17:00, Monday–Friday
Observed:                    03:17
```

This should be considered an anomaly rather than automatic evidence of compromise.

---

## 11. Content Similarity

The system may compare a suspicious message with previous conversation content.

Potential features:

- Subject similarity
- Body similarity
- Signature similarity
- Quoted-text similarity
- Attachment similarity

The objective is to identify messages that appear to reproduce an existing conversation while introducing a different sender identity or communication endpoint.

---

## 12. Detection Correlation

Individual detections should be combined.

```text
BEC-001 Lookalike Domain
        +
BEC-002 Reply-To Mismatch
        +
BEC-004 Authentication Anomaly
        +
BEC-005 New Infrastructure
```

This provides stronger contextual evidence than any individual indicator.

---

## 13. Risk Scoring

The initial scoring system should be transparent.

| Indicator | Weight |
|---|---|
| Lookalike domain | 25 |
| Reply-To mismatch | 20 |
| New conversation participant | 20 |
| Authentication anomaly | 15 |
| New infrastructure | 10 |
| Behavioral anomaly | 10 |

```text
risk_score = Σ indicator_weight
```

Weights should eventually be configurable through a rules/configuration system.

---

## 14. Risk Categories

| Score Range | Category |
|---|---|
| 0–29 | LOW |
| 30–59 | MEDIUM |
| 60–79 | HIGH |
| 80–100+ | CRITICAL |

These thresholds are starting points for the prototype and should be evaluated using test data.

---

## 15. Explainability

Every detection must provide evidence.

**Bad:**

```text
Risk: 85
```

**Good:**

```text
Risk: 85
Reasons:
[+] Sender differs from established participant
[+] Observed domain resembles known participant domain
[+] Reply-To differs from known identity
[+] New sending infrastructure detected
[+] Authentication anomaly detected
```

The analyst should be able to trace the score back to individual observations.

---

## 16. False Positive Handling

The system must account for legitimate cases such as:

- Shared mailboxes
- Mailing lists
- Forwarding services
- Customer support platforms
- CRM systems
- Third-party email providers
- Legitimate aliases
- Delegated mailboxes
- Email security gateways

Detection logic should therefore favor multiple correlated indicators over isolated anomalies.

---

## 17. Machine Learning Extension

Machine learning is a future layer rather than an MVP requirement.

Potential models include:

- Isolation Forest
- Local Outlier Factor
- One-Class SVM
- Autoencoder

**Potential feature vector:**

```json
[
    "sender_frequency",
    "recipient_frequency",
    "sending_hour",
    "response_time",
    "participant_count",
    "subject_similarity",
    "attachment_frequency",
    "infrastructure_frequency",
    "domain_similarity"
]
```

The ML system should operate alongside deterministic rules:

```text
              Email
                │
        ┌───────┴────────┐
        ▼                ▼
 Deterministic       ML Model
 Detection           Detection
        │                │
        └───────┬────────┘
                ▼
          Evidence Fusion
                │
                ▼
           Risk Scoring
```

---

## 18. Evaluation

The detector should be evaluated using controlled synthetic data.

**Initial dataset:**

- Legitimate conversations
- Lookalike-domain attacks
- Display-name impersonation
- Reply-To manipulation
- Thread hijacking
- Authentication anomalies
- Infrastructure anomalies
- Behavioral anomalies

**Evaluation metrics:**

- True Positives
- True Negatives
- False Positives
- False Negatives
- Precision
- Recall
- F1 Score
- Detection Rate
- False Positive Rate

---

## 19. Detection Principle

The central detection principle is:

> An email should be evaluated against the context of the conversation it claims to belong to, rather than judged solely on the contents of the individual message.

This principle drives the architecture of the project.
