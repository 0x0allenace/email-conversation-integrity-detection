# Detection Rules

## 1. Overview

Email Clone Detector uses modular detection rules to identify indicators associated with email impersonation, Business Email Compromise, and conversation hijacking.

Each rule should:

1. Have a unique identifier.
2. Define a detection objective.
3. Identify required evidence.
4. Return structured detection results.
5. Provide an explainable reason.
6. Assign a configurable severity.
7. Avoid claiming maliciousness based solely on one weak indicator.

---

## 2. Rule Format

Rules are stored as YAML files.

```yaml
id: BEC-001
name: Lookalike Domain
description: Detects a sender domain that closely resembles a known participant domain.
severity: high
category:
  - impersonation
  - bec
signals:
  - domain_similarity
  - known_participant
response:
  score: 25
```

---

## 3. BEC-001 — Lookalike Domain

**Objective:** Identify domains that closely resemble domains belonging to known conversation participants.

```text
Known:    supplier.com
Observed: supp1ier.com
```

**Indicators:** known participant domain, observed domain, domain similarity, participant history

**Detection Logic:**

```text
IF
    observed_domain != known_domain
AND
    similarity(observed_domain, known_domain) >= threshold
THEN
    generate BEC-001
```

**Considerations:** the detector must account for legitimate subsidiaries, aliases, newly registered domains, and legitimate third-party senders.

---

## 4. BEC-002 — Reply-To Mismatch

**Objective:** Detect unexpected differences between sender identity and reply destination.

```text
From:     bob@supplier.com
Reply-To: bob.external@gmail.com
```

**Detection Logic:**

```text
IF
    Reply-To exists
AND
    Reply-To differs from known sender identity
AND
    Reply-To is not present in the participant baseline
THEN
    generate BEC-002
```

---

## 5. BEC-003 — New Conversation Participant

**Objective:** Detect a previously unseen sender appearing within an established conversation.

```text
Existing participants: alice@company.com, bob@supplier.com
New:                   bob@supp1ier.com
```

**Detection Logic:**

```text
IF
    sender is not present in conversation baseline
AND
    sender resembles an existing participant
THEN
    generate BEC-003
```

---

## 6. BEC-004 — Authentication Anomaly

**Objective:** Detect unexpected SPF, DKIM, or DMARC authentication results.

**Indicators:** SPF failure, DKIM failure, DMARC failure, authentication policy mismatch

**Detection Logic:**

Authentication anomalies should be correlated with other indicators.

```text
IF
    authentication_failure = true
AND
    identity_anomaly = true
THEN
    increase detection confidence
```

> Authentication failure alone should not automatically classify an email as malicious.

---

## 7. BEC-005 — Sender Infrastructure Anomaly

**Objective:** Identify sending infrastructure that differs from historical observations for a known participant.

**Indicators:** new IP, new hostname, new ASN, new mail server, unexpected infrastructure

**Detection Logic:**

```text
IF
    sender is known
AND
    infrastructure is previously unseen
THEN
    generate infrastructure anomaly
```

---

## 8. BEC-006 — Conversation Hijacking

**Objective:** Identify messages that appear to continue an existing conversation while introducing significant identity or structural inconsistencies.

Potential indicators: new participant, identity mismatch, Reply-To mismatch, authentication anomaly, new infrastructure, thread metadata anomaly.

**Example Correlation:**

```text
BEC-003 + BEC-002 + BEC-004  →  may contribute to a BEC-006 detection
```

---

## 9. BEC-007 — Behavioral Communication Anomaly

**Objective:** Identify communication behavior that deviates from an established baseline.

Potential signals: unusual sending time, unusual recipient, unusual frequency, unusual response time, unusual attachment behavior.

This rule is intended to become more sophisticated as historical data becomes available.

---

## 10. BEC-008 — Display Name Impersonation

**Objective:** Detect cases where a known participant's display name is associated with a different email address.

```text
Known:    John Smith <john@company.com>
Observed: John Smith <john@attacker.example>
```

**Detection Logic:**

```text
IF
    observed_display_name matches known_display_name
AND
    observed_address differs from known_address
THEN
    generate BEC-008
```

---

## 11. BEC-009 — Thread Metadata Anomaly

**Objective:** Identify inconsistencies in email threading metadata.

**Relevant fields:** Message-ID, In-Reply-To, References, Subject

Potential indicators: missing expected references, unexpected parent Message-ID, inconsistent thread relationships.

> Thread metadata should be treated as supporting evidence rather than a definitive identity mechanism.

---

## 12. BEC-010 — Suspicious Conversation Clone

**Objective:** Identify messages that appear to reproduce an established conversation while introducing identity or infrastructure anomalies.

Potential signals: high subject similarity, high body similarity, same recipients, same signature, different sender, different domain, different infrastructure.

**Example:**

```text
Conversation:  Invoice #48291 (×3)
Observed:      Invoice #48291
  Content similarity:  High
  Sender identity:     Different
  Domain:              Similar
  Infrastructure:      New
```

---

## 13. Rule Correlation

Rules should be independently testable but capable of correlation.

```text
BEC-001  Lookalike Domain
   │
   ├──────────────┐
   ▼              ▼
BEC-002       BEC-004
   │              │
   └──────┬───────┘
          ▼
       BEC-006
```

This allows the system to distinguish between isolated anomalies and multiple correlated indicators.

---

## 14. Severity

Initial severity categories:

- LOW
- MEDIUM
- HIGH
- CRITICAL

Severity should be based on the rule and contextual evidence, and should remain configurable.

---

## 15. Detection Event Format

Every rule should produce a consistent result.

```json
{
  "rule_id": "BEC-001",
  "rule_name": "Lookalike Domain",
  "matched": true,
  "severity": "high",
  "score": 25,
  "evidence": {
    "known_domain": "supplier.com",
    "observed_domain": "supp1ier.com",
    "similarity": 0.91
  },
  "explanation": "Observed sender domain closely resembles a known conversation participant domain."
}
```

---

## 16. Rule Design Principles

**Evidence Based**
Rules must rely on observable data.

**Explainable**
Analysts must understand why a rule triggered.

**Modular**
Rules should operate independently.

**Testable**
Each rule should have positive and negative test cases.

**Context Aware**
Rules should use conversation history whenever possible.

**Conservative**
Weak indicators should not automatically produce high-confidence conclusions.

---

## 17. Rule Testing

Each rule should have a positive test, a negative test, edge cases, and false-positive scenarios.

**Example — BEC-001:**

| Case | Domains |
|---|---|
| Positive | `supplier.com` → `supp1ier.com` |
| Negative | `supplier.com` → `supplier.co.uk` |
| Edge | `supplier.com` → `supplier.co` |

---

## 18. Planned Rule Expansion

Future rules may include:

- BEC-011 — Domain Age Anomaly
- BEC-012 — New Recipient Anomaly
- BEC-013 — Unusual Attachment Pattern
- BEC-014 — Suspicious URL Change
- BEC-015 — Sender Reputation Anomaly
- BEC-016 — Conversation Timing Anomaly
- BEC-017 — Payment Instruction Change
- BEC-018 — Account Compromise Behavior

These should only be implemented when the required evidence and data sources are available.
