# System Architecture

## 1. Overview

Email Clone Detector is designed as a modular email security analysis platform.

The architecture separates email collection, parsing, forensic analysis, detection, scoring, and alerting so that individual components can be developed and tested independently.

The primary objective is to determine whether a newly observed email is consistent with an established business conversation.

---

## 2. High-Level Architecture

```text
                         ┌──────────────────────┐
                         │     Email Source     │
                         │  .eml / IMAP / API   │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │     Email Parser     │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │ Header Normalization │
                         └──────────┬───────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │  Conversation Reconstruction  │
                    └───────────────┬───────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                      ▼
       ┌────────────┐       ┌──────────────┐       ┌──────────────┐
       │  Identity  │       │Authentication│       │Infrastructure│
       │  Analysis  │       │   Analysis   │       │   Analysis   │
       └─────┬──────┘       └──────┬───────┘       └──────┬───────┘
             │                     │                      │
             └─────────────────────┼──────────────────────┘
                                    ▼
                         ┌──────────────────────┐
                         │  Behavioral Analysis │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │   Detection Engine   │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │     Risk Scoring     │
                         └──────────┬───────────┘
                                    │
                   ┌────────────────┴────────────────┐
                   ▼                                  ▼
          ┌──────────────────┐              ┌──────────────────┐
          │ Detection Event  │              │   Alert Engine   │
          └────────┬─────────┘              └────────┬─────────┘
                   │                                  │
                   ▼                                  ▼
          ┌──────────────────┐              ┌──────────────────┐
          │ SIEM Integration │              │  Analyst / Users │
          └──────────────────┘              └──────────────────┘
```

---

## 3. Component Responsibilities

### 3.1 Parser

Responsible for converting raw email messages into a normalized internal representation.

- **Input:** `.eml`
- **Output:** `NormalizedEmail`

The parser should extract:

- Sender
- Recipients
- Subject
- Body
- Attachments
- Headers
- Timestamps
- Message-ID
- Threading metadata

### 3.2 Headers

Responsible for analyzing security-relevant headers.

Important headers include:

```text
From
To
Cc
Reply-To
Return-Path
Message-ID
In-Reply-To
References
Date
Received
Authentication-Results
Received-SPF
DKIM-Signature
```

The module should preserve the original header values while also producing normalized fields for analysis.

### 3.3 Authentication

Responsible for evaluating email authentication evidence.

The initial implementation should support analysis of:

- SPF
- DKIM
- DMARC

The module should not automatically treat a single authentication failure as proof of malicious activity. Authentication results are evidence that should be combined with other indicators.

### 3.4 Conversation

Responsible for reconstructing relationships between messages.

Potential correlation fields include:

- Message-ID
- In-Reply-To
- References
- Subject
- Participants
- Conversation identifiers

The module creates a conversation baseline containing known participants and historical characteristics.

### 3.5 Identity

Responsible for comparing observed sender identities against known participants.

Analysis includes:

- Email address
- Display name
- Domain
- Local part
- Reply-To
- Return-Path
- Participant history

The identity module should detect:

- Exact identity changes
- Display-name impersonation
- Lookalike domains
- Unexpected participants
- Sender/reply inconsistencies

### 3.6 Infrastructure

Responsible for analyzing sending infrastructure.

Potential data:

- IP address
- Hostname
- Reverse DNS
- ASN
- Mail server
- Geographic information
- Historical infrastructure

The module establishes whether the observed infrastructure is consistent with previously observed messages.

### 3.7 Behavior

Responsible for analyzing communication patterns.

Potential features:

- Sending time
- Response time
- Sender frequency
- Recipient frequency
- Participant frequency
- Subject similarity
- Attachment frequency
- Communication frequency

Behavioral analysis should initially remain descriptive. Machine-learning detection can be added after a sufficient baseline exists.

### 3.8 Detection Engine

The detection engine evaluates individual rules (e.g. `BEC-001`, `BEC-002`, `BEC-003`, ...).

Each rule should return structured evidence:

```json
{
  "rule_id": "BEC-001",
  "matched": true,
  "severity": "high",
  "evidence": {
    "known_domain": "supplier.com",
    "observed_domain": "supp1ier.com"
  }
}
```

### 3.9 Scoring

The scoring module combines detection results.

| Rule | Indicator | Score |
|---|---|---|
| BEC-001 | Lookalike Domain | +25 |
| BEC-002 | Reply-To Mismatch | +20 |
| BEC-004 | Authentication Issue | +20 |
| BEC-005 | New Infrastructure | +10 |
| | **Total** | **75** |

The score should remain explainable.

### 3.10 Alerting

The alerting module converts detection results into notifications.

Potential destinations:

- SOC dashboard
- Email
- Webhook
- SIEM
- Security mailbox

The alerting layer should support configurable response policies.

---

## 4. Data Flow

```text
Raw Email
    │
    ▼
Parse
    │
    ▼
Normalize
    │
    ▼
Store / Retrieve Conversation
    │
    ▼
Build Baseline
    │
    ▼
Analyze New Message
    │
    ├── Identity
    ├── Authentication
    ├── Infrastructure
    └── Behavior
    │
    ▼
Run Detection Rules
    │
    ▼
Aggregate Evidence
    │
    ▼
Calculate Risk
    │
    ▼
Generate Detection Event
    │
    ├── Database
    ├── SIEM
    └── Alerting
```

---

## 5. Internal Detection Event

All detections should use a consistent event structure.

```json
{
  "event_type": "email_security_detection",
  "rule_id": "BEC-001",
  "severity": "high",
  "risk_score": 82,
  "sender": "bob@supp1ier.com",
  "known_sender": "bob@supplier.com",
  "conversation_id": "conversation-123",
  "indicators": [
    "lookalike_domain",
    "new_participant"
  ],
  "timestamp": "2026-09-21T15:00:00Z"
}
```

---

## 6. Storage Architecture

The initial MVP can use SQLite for local development. Production-oriented deployments should support PostgreSQL.

**Conceptual entities:**

- Email
- Conversation
- Participant
- Identity
- Infrastructure
- Detection
- Alert

**Relationships:**

```text
Conversation
     │
     ├── Email
     │     ├── Sender
     │     ├── Recipients
     │     └── Authentication
     │
     ├── Participants
     │
     └── Detections
```

---

## 7. Integration Boundary

External integrations should be isolated from the core detection engine.

```text
                 Core Engine
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
        Splunk     Elastic     Wazuh
```

This allows the detection engine to operate independently of any particular SIEM.

---

## 8. Security Boundaries

The system should treat email content as untrusted input.

Security controls should include:

- Input validation
- Safe MIME parsing
- Attachment isolation
- Size limits
- Parser error handling
- Logging
- Authentication for APIs
- Authorization for administrative functions
- Secrets stored outside source code
- No execution of email attachments

> Email attachments must be treated as untrusted files and should never be executed by the parser.

---

## 9. MVP Architecture

The first implementation should deliberately exclude complex external integrations.

```text
.eml
 │
 ▼
Parser
 │
 ▼
Header Analysis
 │
 ▼
Conversation Reconstruction
 │
 ▼
Identity Detection
 │
 ▼
Authentication Analysis
 │
 ▼
Risk Scoring
 │
 ▼
JSON / CLI Alert
```

Once this pipeline is stable, API, database, SIEM, and mailbox integrations can be introduced incrementally.
