# Email Conversation Integrity Detection

**Detect • Investigate • Respond**

An open-source Blue Team detection engine designed to identify suspicious email messages that appear to impersonate, clone, or hijack an established business email conversation.

The project focuses on Business Email Compromise (BEC), email impersonation, conversation hijacking, sender identity anomalies, abnormal communication behavior, and suspicious message-content patterns by analyzing email headers, authentication results, sender identity, conversation participants, infrastructure, behavioral baselines, and historical message content.

---

## Project Status

**Development Stage:** MVP / Active Development

The current implementation provides:

- Email parsing and normalization
- Header extraction and normalization
- Sender identity analysis
- Conversation participant analysis
- Lookalike-domain detection
- Reply-To mismatch detection
- Thread participant anomaly detection
- SPF/DKIM/DMARC analysis
- Sender infrastructure anomaly detection
- Conversation hijacking analysis
- Deterministic behavioral communication anomaly detection
- Historical sender behavior analysis
- Historical recipient behavior analysis
- Historical sending frequency analysis
- Historical recipient frequency analysis
- Historical recipient co-occurrence analysis
- Historical recipient role analysis
- Message content anomaly detection
- Historical subject similarity analysis
- Historical body similarity analysis
- Historical body-length analysis
- Explainable per-rule risk scoring
- Structured detection indicators
- FastAPI API
- PostgreSQL persistence
- Docker / Docker Compose deployment
- Normalized SIEM event generation
- SIEM integration management
- Splunk integration
- Elastic integration
- Wazuh integration
- Application-level SIEM configuration
- Automated test coverage

The project is being developed incrementally. Deterministic and explainable detection techniques are being established before introducing machine-learning-based behavioral anomaly detection.

---

## Problem

Business email attacks do not always look like traditional phishing. An attacker may:

- Impersonate an existing participant
- Register a lookalike domain
- Spoof a display name
- Manipulate the Reply-To address
- Insert themselves into an existing conversation
- Reproduce an existing email thread
- Use a compromised legitimate mailbox
- Send messages from previously unseen infrastructure
- Modify communication patterns
- Use familiar subjects, signatures, and conversation history
- Alter established recipient relationships or recipient roles
- Reuse familiar message content in suspicious circumstances
- Produce unusually long or short messages compared with historical communication

**Example:**

| Message | Address |
|---|---|
| Legitimate participant | `John Smith <john@supplier.com>` |
| Suspicious message | `John Smith <john@supp1ier.com>` |

The display name and domain may appear convincing to a human recipient while the underlying identity is different.

Similarly, an attacker attempting to continue an established conversation may reproduce familiar subject lines or message content while introducing other identity, infrastructure, behavioral, or content inconsistencies.

The purpose of Email Conversation Integrity Detection is to identify these inconsistencies automatically and provide an explainable risk assessment that can support SOC investigation.

---

## Objectives

1. Parse and normalize email messages.
2. Extract security-relevant email headers.
3. Establish known participants within a conversation.
4. Detect sender identity inconsistencies.
5. Detect lookalike domains.
6. Analyze Reply-To and sender relationships.
7. Evaluate SPF, DKIM, and DMARC results where available.
8. Identify suspicious infrastructure changes.
9. Detect abnormal communication behavior.
10. Analyze historical sender and recipient communication patterns.
11. Analyze historical message-content patterns.
12. Generate explainable risk scores.
13. Produce SOC-friendly detection results.
14. Preserve structured detection evidence.
15. Normalize detection results into SIEM events.
16. Integrate detections with SIEM platforms.
17. Provide an extensible foundation for behavioral and content-based anomaly detection.
18. Provide a foundation for future machine-learning-based anomaly detection.

---

## Quick Start

### Prerequisites

You need:

- Python 3.13+
- Docker Desktop
- Docker Compose
- Git

Docker is recommended for running the API and PostgreSQL database together.

### Clone the Repository

```bash
git clone https://github.com/0x0allenace/email-conversation-integrity-detection.git
cd email-conversation-integrity-detection
```

### Start the Application

Build and start the API and PostgreSQL containers:

```bash
docker compose up -d --build
```

Check the container status:

```bash
docker compose ps
```

The expected services are:

- `ecid-api`
- `ecid-postgres`

The PostgreSQL container should report as healthy.

### Initialize the Database

Initialize the database tables:

```bash
docker compose exec api python -m src.database.init_db
```

The current MVP uses SQLAlchemy to create the required PostgreSQL tables.

### Verify the API

**Health check:**

```bash
curl http://localhost:8000/health
```

Expected:

```json
{
  "status": "ok",
  "service": "email-conversation-integrity-detection"
}
```

**Readiness check:**

```bash
curl http://localhost:8000/ready
```

Expected:

```json
{
  "status": "ready",
  "service": "email-conversation-integrity-detection"
}
```

### Analyze an Email

The API accepts `.eml` files.

For example, analyze the included legitimate sample:

```bash
curl -X POST \
  -F "email_file=@samples/legitimate/normal-conversation.eml" \
  -F "known_domain=supplier.com" \
  -F "known_display_name=Bob Supplier" \
  -F "known_participants=bob@supplier.com" \
  -F "known_participants=alice@company.com" \
  -F "known_hosts=mail.supplier.com" \
  -F "known_hosts=relay.supplier.com" \
  -F "known_ip_addresses=192.0.2.10" \
  -F "known_ip_addresses=192.0.2.20" \
  -F 'known_behavior={}' \
  http://localhost:8000/analyze
```

> The participant baseline should contain every established participant of the conversation. Omitting an established participant can cause BEC-003 to identify that participant as unexpected.

The API returns:

- Parsed email information
- Sender identity
- Conversation participants
- Authentication results
- Infrastructure information
- Detection results
- Per-rule risk scores
- Detection indicators and applicable evidence

### Retrieve Stored Analyses

List persisted analyses:

```bash
curl http://localhost:8000/analyses
```

Retrieve a specific analysis:

```bash
curl http://localhost:8000/analyses/1
```

The persisted analysis includes the original analysis result and the individual detection records.

### Database

The Docker environment uses PostgreSQL.

Connect directly to the database:

```bash
docker compose exec db psql -U postgres -d email_integrity
```

List tables:

```sql
\dt
```

The current schema includes:

- `analyses`
- `detections`

### Stop the Environment

Stop the containers:

```bash
docker compose down
```

To stop the containers and remove the PostgreSQL volume:

```bash
docker compose down -v
```

> **Warning:** Removing the volume deletes the locally persisted PostgreSQL data.

---

## API

The current API provides:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check |
| POST | `/analyze` | Analyze an uploaded `.eml` |
| GET | `/analyses` | List persisted analyses |
| GET | `/analyses/{id}` | Retrieve one persisted analysis |

FastAPI also provides interactive API documentation when the application is running: `http://localhost:8000/docs`

---

## Core Detection Concept

The system establishes a baseline from known participants, sender identity, infrastructure, behavioral information, and historical communication data. Newly received messages are then compared against those baselines.

```text
                         Incoming Email
                               │
                               ▼
                        Email Parser
                               │
                               ▼
                      Header / Body Extraction
                               │
                               ▼
                       Analysis Context
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
      Identity           Authentication       Infrastructure
      Analysis              Analysis             Analysis
          │                    │                    │
          └────────────────────┼────────────────────┘
                               ▼
                    Conversation / Behavior
                          / Content Analysis
                               │
                               ▼
                       Detection Engine
                               │
                               ▼
                         Risk Scoring
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
                 Normal               Suspicious
                                          │
                                          ▼
                                SIEM / SOC Workflow
```

The detection engine is designed around deterministic, observable indicators so that analysts can investigate the evidence behind each detection.

---

## Detection Rules

The current detection engine contains the following rules:

| Rule | Detection | Severity | Status |
|---|---|---|---|
| BEC-001 | Lookalike Domain | HIGH | ✅ Implemented |
| BEC-002 | Reply-To Mismatch | HIGH | ✅ Implemented |
| BEC-003 | Thread Participant Anomaly | HIGH | ✅ Implemented |
| BEC-004 | Authentication Anomaly | HIGH | ✅ Implemented |
| BEC-005 | Sender Infrastructure Anomaly | MEDIUM | ✅ Implemented |
| BEC-006 | Conversation Hijacking | HIGH | ✅ Implemented |
| BEC-007 | Behavioral Communication Anomaly | MEDIUM | ⏳ Expanding |
| BEC-008 | Message Content Anomaly | MEDIUM | ✅ Implemented |

---

## Initial Detection Categories

### BEC-001 — Lookalike Domain

Detects domains that closely resemble a previously trusted participant.

```text
supplier.com
supp1ier.com
```

The current implementation uses deterministic domain similarity analysis.

### BEC-002 — Reply-To Mismatch

Detects situations where the apparent sender and reply destination do not correspond.

```text
From: John Smith <john@supplier.com>
Reply-To: john.supplier@gmail.com
```

### BEC-003 — Thread Participant Anomaly

Detects a participant appearing in an established conversation that is not present in the supplied participant baseline.

This detection depends on the quality of the conversation baseline supplied to the analysis engine.

### BEC-004 — Authentication Anomaly

Analyzes available authentication results:

- SPF
- DKIM
- DMARC

The detection uses authentication information available in the analyzed message.

### BEC-005 — Sender Infrastructure Anomaly

Detects changes in infrastructure associated with a known sender.

**Current indicators include:**

- Previously unseen sending host
- Previously unseen sending IP address

**Future enrichment may include:**

- ASN
- Geographic origin
- Reverse DNS
- Sender infrastructure reputation

### BEC-006 — Conversation Hijacking

Detects suspicious messages that appear to continue an existing conversation while containing inconsistencies involving:

- Identity
- Headers
- Infrastructure
- Conversation structure
- Authentication
- Participant relationships

The current implementation combines conversation/thread indicators with sender identity and available conversation context.

### BEC-007 — Behavioral Communication Anomaly

Identifies unusual communication behavior compared with an established sender or conversation baseline.

The current implementation uses deterministic behavioral analysis. It can evaluate both explicitly supplied behavioral baselines and historical observations retrieved for a known sender.

**Current behavioral signals include:**

- Typical sending hours
- Typical sending days
- Typical sender timezone offset
- Historical sending-hour range
- Historical sender behavior
- Historical recipient behavior
- Historical sending frequency
- Historical recipient frequency
- Historical recipient co-occurrence
- Historical recipient role relationships

#### Sending Hour

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

#### Day of Week

The `typical_days` baseline defines the weekdays on which communication is normally expected.

The observed weekday is derived from the parsed email `Date` header using Python's weekday representation:

| Value | Day |
|---|---|
| 0 | Monday |
| 1 | Tuesday |
| 2 | Wednesday |
| 3 | Thursday |
| 4 | Friday |
| 5 | Saturday |
| 6 | Sunday |

**For example:**

```text
Established behavior:
  Days: Monday–Friday
Observed:
  Sunday
Indicator:
  - Message sent outside established communication days
```

#### Timezone Offset

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
Observed:
  Date header offset: -0500
Indicator:
  - Message sent from an unexpected timezone offset
```

> This signal evaluates the timezone offset declared by the message's `Date` header. It does not establish the sender's physical location or prove that the sender was actually operating from that timezone.

#### Historical Sender Behavior

When historical observations are available for a known sender, BEC-007 can compare the current message against previously observed communication behavior.

Historical observations can contribute information about:

- Previously observed sending hours
- Historical sending frequency
- Historical recipient relationships
- Historical recipient frequency
- Historical recipient co-occurrence
- Historical recipient role relationships

> Historical analysis requires a minimum number of valid observations before a behavioral relationship is established. This reduces the likelihood of treating a single historical message as a reliable behavioral baseline.

#### Historical Sending Frequency

The sending-frequency signal evaluates the interval between the current message and historical messages from the same sender.

A message may be considered behaviorally unusual when it occurs at a substantially different cadence from the sender's established historical communication frequency.

```text
Historical behavior:
  Typical interval: 60 minutes
Observed:
  Current interval: 5 minutes
Indicator:
  - Message sent at an unusually high communication frequency
```

This signal is intended to identify changes in communication cadence rather than determine whether a specific sending interval is inherently malicious.

#### Historical Recipient Behavior

BEC-007 can compare the recipients of the current message with recipients observed in the sender's historical communication.

The analysis distinguishes between:

- Previously observed recipients
- Recipients that are unusual for the sender
- Recipient relationships that are historically established
- Recipient relationships that have not previously been observed

```text
Historical recipients:
  alice@company.com
  finance@company.com
  procurement@company.com
Observed:
  hr@company.com
Indicator:
  - Message contains a historically unusual recipient
```

Recipient analysis considers both `To` and `Cc` recipients.

#### Historical Recipient Frequency

Recipient frequency measures how often a particular recipient has appeared in the sender's historical messages.

A recipient may be considered unusual when the historical frequency of that recipient falls below the configured behavioral threshold.

This provides a more granular signal than simply asking whether the recipient has ever appeared before.

#### Historical Recipient Co-Occurrence

Recipient co-occurrence evaluates whether recipients that appear together in the current message have historically appeared together in the same communication.

**For example:**

```text
Historical behavior:
  To: alice@company.com
  Cc: finance@company.com
Observed:
  To: alice@company.com
  Cc: hr@company.com
Indicator:
  - Message contains an unusual recipient relationship
```

The co-occurrence analysis is based on normalized recipient pairs and requires sufficient historical observations before an established relationship is inferred.

An unseen recipient pair can be treated as having no established historical co-occurrence, while previously established recipient pairs can be compared against their historical frequency.

#### Historical Recipient Role Anomaly

Recipient role analysis extends recipient co-occurrence analysis by evaluating whether established recipient pairs normally occupy the same `To` and `Cc` roles.

**For example:**

```text
Historical behavior:
  To: alice@company.com
  Cc: finance@company.com
Observed:
  To: finance@company.com
  Cc: alice@company.com
Indicator:
  - Message contains a historically unusual recipient role relationship
```

This signal is different from recipient co-occurrence. The recipients may both be familiar and may normally appear together, while their current `To`/`Cc` roles differ from the established historical relationship.

**Recipient role analysis:**

- Requires an established recipient relationship
- Uses normalized `To` and `Cc` recipients
- Treats `To` as the deterministic role when a recipient appears in both `To` and `Cc`
- Requires sufficient historical observations
- Does not replace the recipient co-occurrence detector
- Does not independently classify an entirely unseen recipient pair

#### Multiple Behavioral Anomalies

BEC-007 can report multiple behavioral inconsistencies for the same message.

```text
Established behavior:
  Hours:             08:00–17:00
  Days:              Monday–Friday
  Timezone offsets:  +0100
Historical behavior:
  Normal recipients:
    alice@company.com
    finance@company.com
Observed:
  Sunday 02:30 -0500
  Recipient relationship differs from historical behavior
Indicators:
  - Message sent outside established communication hours
  - Message sent outside established communication days
  - Message sent from an unexpected timezone offset
  - Message contains a historically unusual recipient relationship
```

The indicators are independently evaluated and returned together when multiple baseline conditions are violated.

#### Behavioral Baselines

Explicit behavioral baselines are optional.

- If `typical_hours` is supplied, the observed sending hour is evaluated.
- If `typical_days` is supplied, the observed weekday is evaluated.
- If `typical_timezone_offsets` is supplied, the observed `Date` header timezone offset is evaluated.
- Historical observations can provide additional behavioral signals when sufficient historical data is available.
- An empty behavioral baseline does not independently produce a behavioral detection.

The detection result preserves behavioral evidence used by the rule, including applicable:

- Observed hour
- Typical hours
- Observed weekday
- Typical days
- Observed timezone offset
- Typical timezone offsets
- Historical observations
- Historical recipient frequencies
- Historical recipient co-occurrences
- Historical recipient role frequencies
- Behavioral indicators

> Behavioral signals should only be introduced when the system has a clearly defined observation source or baseline for that signal.

### BEC-008 — Message Content Anomaly

Detects suspicious differences between the current message content and historical messages associated with the same conversation or sender.

The current implementation uses deterministic text comparison rather than machine learning.

BEC-008 evaluates three independent content signals:

- Subject similarity
- Body similarity
- Body length

Historical observations must contain sufficient valid subject/body data before content comparison is performed.

The current implementation requires a minimum of 3 qualifying historical observations.

#### Subject Similarity

The current subject is normalized before comparison.

**Normalization includes:**

- Lowercasing
- Collapsing whitespace
- Removing repeated `Re:` / `Fw:` / `Fwd:` prefixes

The normalized current subject is compared against historical subjects using Python's standard-library `difflib.SequenceMatcher`.

The current subject is considered anomalous when its maximum similarity to the historical subjects falls below:

```text
Subject similarity threshold: 0.50
```

**Example:**

```text
Historical subjects:
  Payment confirmation
  Payment confirmation
  Payment confirmation
Observed:
  Urgent password reset request
Indicator:
  - Subject similarity below historical threshold
```

#### Body Similarity

The message body is normalized before comparison.

**Normalization includes:**

- Lowercasing
- Collapsing whitespace

The normalized current body is compared with historical message bodies using `SequenceMatcher`.

The current body is considered anomalous when its maximum similarity to the historical bodies falls below:

```text
Body similarity threshold: 0.50
```

**Example:**

```text
Historical body:
  Please find the attached invoice for this month's services.
Observed body:
  Please urgently change the beneficiary account before processing payment.
Indicator:
  - Body similarity below historical threshold
```

#### Body Length Anomaly

BEC-008 also compares the current body length against the median historical body length.

The current implementation considers the body length anomalous when it is:

- More than 2.0x the historical median, or
- Less than 0.5x the historical median

```text
Historical median body length:
  500 characters
Observed:
  1500 characters
Indicator:
  - Body length differs substantially from historical behavior
```

A zero historical median is handled separately so that a non-empty current body can still be identified as anomalous.

#### Multiple Content Anomalies

BEC-008 evaluates the subject, body, and body-length signals independently.

A single message may therefore produce multiple content indicators:

```text
Historical behavior:
  Similar subject
  Similar body
  Typical body length
Observed:
  Unrelated subject
  Unrelated body
  3x historical median body length
Indicators:
  - Subject similarity below historical threshold
  - Body similarity below historical threshold
  - Body length differs substantially from historical behavior
```

The detection result preserves structured evidence for the individual content signals.

#### Historical Content Baseline

BEC-008 uses historical observations supplied to the detection engine.

The historical observations should represent legitimate communication associated with the sender or conversation being evaluated.

> Historical content analysis depends on the quality and representativeness of the historical baseline. A poisoned, incomplete, or unrelated baseline can reduce detection accuracy.

#### Current Scope

BEC-008 currently analyzes:

- Subject text
- Plain message body content
- Historical subject similarity
- Historical body similarity
- Historical body length

Attachments are currently outside the scope of BEC-008.

Future content analysis may incorporate richer semantic or attachment-aware techniques.

---

## Risk Scoring

The detection engine produces an explainable risk score for each detection rule. Scores are derived from observable detection indicators rather than relying on an opaque classification.

```text
Domain mismatch
        +
Authentication failure
        +
Unexpected participant
        +
Behavioral anomaly
        +
Content anomaly
        ↓
Explainable risk contribution
```

The current scoring implementation assigns rule-specific contributions and caps each individual detection score at 100.

**Current risk contributions include:**

| Indicator | Contribution |
|---|---|
| Domain mismatch | +50 |
| Display name matches known participant | +20 |
| Authentication failure | +30 |
| Unexpected participant | +30 |
| Infrastructure anomaly | +20 |
| Thread reuse anomaly | +20 |
| Behavioral anomaly | +20 |
| Content anomaly | +20 |

The scoring model is rule-aware, so not every indicator contributes to every rule.

> The numerical score should not be treated as a standalone verdict. Detection results should always be investigated using the underlying indicators and evidence.

---

## Structured Detection Evidence

Detection results preserve structured indicators when a rule produces machine-readable evidence.

Indicators may contain either:

- Human-readable detection messages
- Structured evidence objects

For example, content anomaly evidence can preserve individual measurements rather than only returning a generic detection message.

**This allows downstream components such as:**

- API responses
- PostgreSQL persistence
- SIEM event generation
- SOC dashboards
- Future analytics

to retain the evidence generated by the detection rule.

The structured indicator model also provides a foundation for future enrichment without requiring the detection engine to flatten all evidence into strings.

---

## Example Detection

**Established Conversation**

```text
Alice <alice@company.com>
        │
        ▼
Bob <bob@supplier.com>
        │
        ▼
Alice <alice@company.com>
```

**Suspicious Message**

```text
Bob <bob@supp1ier.com>
```

The detector can identify evidence such as:

```text
Known identity:    bob@supplier.com
Observed identity: bob@supp1ier.com
```

**Potential indicators include:**

- Display name matches a known participant
- Domain differs from the known participant
- Domain is visually similar
- Sender has not previously appeared in the supplied baseline

The resulting detection is accompanied by the applicable rule, indicators, details, and risk contribution.

---

## SIEM Integration

The project includes an application-level SIEM integration layer.

Detection results can be converted into a normalized `SIEMEvent` before being dispatched to a configured SIEM provider.

```text
Detection Result
       │
       ▼
SIEM Event Adapter
       │
       ▼
Normalized SIEM Event
       │
       ▼
SIEM Service
       │
       ▼
Integration Manager
       │
 ┌─────┼─────┐
 ▼     ▼     ▼
Splunk Elastic Wazuh
```

### Supported Providers

| Provider | Status | Authentication |
|---|---|---|
| Splunk | ✅ Implemented | HEC token |
| Elastic | ✅ Implemented | API key or basic authentication |
| Wazuh | ✅ Implemented | Username/password |

The application currently configures one SIEM provider at startup.

### Application SIEM Configuration

SIEM configuration is controlled through environment variables.

**Core settings:**

```text
ECID_SIEM_ENABLED
ECID_SIEM_PROVIDER
ECID_SIEM_URL
ECID_SIEM_TOKEN
ECID_SIEM_USERNAME
ECID_SIEM_PASSWORD
ECID_SIEM_INDEX
ECID_SIEM_SOURCE
ECID_SIEM_TIMEOUT
```

SIEM integration is disabled by default.

**Example Splunk configuration:**

```bash
export ECID_SIEM_ENABLED=true
export ECID_SIEM_PROVIDER=splunk
export ECID_SIEM_URL=https://splunk.example.com:8088
export ECID_SIEM_TOKEN=<your-hec-token>
export ECID_SIEM_INDEX=ecid-events
export ECID_SIEM_SOURCE=email-conversation-integrity-detection
export ECID_SIEM_TIMEOUT=10.0
```

**Example Elastic configuration using an API key:**

```bash
export ECID_SIEM_ENABLED=true
export ECID_SIEM_PROVIDER=elastic
export ECID_SIEM_URL=https://elastic.example.com:9200
export ECID_SIEM_TOKEN=<your-api-key>
export ECID_SIEM_INDEX=ecid-events
export ECID_SIEM_TIMEOUT=10.0
```

**Example Elastic configuration using basic authentication:**

```bash
export ECID_SIEM_ENABLED=true
export ECID_SIEM_PROVIDER=elastic
export ECID_SIEM_URL=https://elastic.example.com:9200
export ECID_SIEM_USERNAME=<your-username>
export ECID_SIEM_PASSWORD=<your-password>
export ECID_SIEM_INDEX=ecid-events
export ECID_SIEM_TIMEOUT=10.0
```

**Example Wazuh configuration:**

```bash
export ECID_SIEM_ENABLED=true
export ECID_SIEM_PROVIDER=wazuh
export ECID_SIEM_URL=https://wazuh.example.com:55000
export ECID_SIEM_USERNAME=<your-username>
export ECID_SIEM_PASSWORD=<your-password>
export ECID_SIEM_INDEX=ecid-events
export ECID_SIEM_TIMEOUT=10.0
```

> **Security:** Do not commit SIEM tokens, passwords, API keys, or other secrets to the repository. Use environment variables or an appropriate secret-management mechanism.

### SIEM Event Model

The normalized event contains security-relevant fields such as:

- Event type
- Timestamp
- Message ID
- Sender email
- Sender domain
- Recipients
- Subject
- Detection rule
- Severity
- Match status
- Risk score
- Indicators
- Detection details
- Authentication context
- Infrastructure context
- Conversation context
- Event source
- Schema version

Structured detection indicators are preserved when provided by the detection rule.

This normalized layer keeps the detection engine independent from individual SIEM platforms.

---

## Project Structure

```text
email-conversation-integrity-detection/
│
├── README.md
├── LICENSE
├── .dockerignore
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── pytest.ini
│
├── docs/
│   ├── architecture.md
│   ├── detection-methodology.md
│   ├── threat-model.md
│   └── detection-rules.md
│
├── src/
│   ├── api/
│   ├── authentication/
│   ├── conversation/
│   ├── database/
│   ├── detection/
│   ├── engine/
│   ├── identity/
│   ├── infrastructure/
│   ├── integrations/
│   │   └── siem/
│   ├── parser/
│   ├── rules/
│   └── scoring/
│
├── tests/
│
├── samples/
│   ├── legitimate/
│   ├── lookalike-domain/
│   ├── reply-to-manipulation/
│   └── thread-hijacking/
│
└── scripts/
```

The SIEM integration implementation currently lives under:

```text
src/integrations/siem/
├── __init__.py
├── base.py
├── elastic.py
├── event.py
├── event_adapter.py
├── factory.py
├── manager.py
├── service.py
├── splunk.py
└── wazuh.py
```

Detection rules are registered through the detection engine's rule registry.

---

## Technology Stack

| Component | Technology |
|---|---|
| Language | Python 3.13+ |
| API | FastAPI |
| Database | PostgreSQL |
| ORM | SQLAlchemy |
| Email Parsing | Python `email` package |
| Authentication Analysis | SPF / DKIM / DMARC header analysis |
| Text Comparison | Python `difflib.SequenceMatcher` |
| Containers | Docker / Docker Compose |
| SIEM | Splunk / Elastic / Wazuh |
| Testing | Pytest |
| Future ML | Scikit-learn / PyTorch / TensorFlow |

Additional technologies will be introduced as the relevant detection and research components are implemented.

---

## Development Philosophy

The project follows a layered detection approach:

```text
Layer 1 — Email Forensics
        ↓
Layer 2 — Identity Analysis
        ↓
Layer 3 — Authentication Analysis
        ↓
Layer 4 — Infrastructure Analysis
        ↓
Layer 5 — Conversation Analysis
        ↓
Layer 6 — Behavioral Analysis
        ↓
Layer 7 — Message Content Analysis
        ↓
Layer 8 — Risk Scoring
        ↓
Layer 9 — SIEM / SOC Integration
```

The implementation prioritizes deterministic and explainable detections before introducing machine-learning-based anomaly detection.

Each layer is designed to produce evidence that can be inspected by a security analyst rather than relying exclusively on a final classification.

---

## Security Design Principles

**Explainability**
Every detection should explain why the message was considered suspicious.

**Evidence First**
Detections should be based on observable email evidence rather than assumptions.

**Baseline Awareness**
Behavioral and content-based detections should be grounded in a clearly defined historical or explicit baseline.

**Least Privilege**
Future integrations should request only the permissions required to inspect and alert on email.

**Safe Testing**
The project uses synthetic emails and controlled laboratory environments.

**Human Verification**
High-impact actions should not be performed automatically solely because a message receives a high risk score.

**Separation of Detection and Enrichment**
Deterministic detection logic should remain understandable and testable independently from future enrichment and machine-learning components.

**Structured Evidence**
Detection rules should preserve machine-readable evidence where useful so downstream systems can investigate and correlate detections.

---

## Testing

The project uses Pytest for automated testing.

Run the complete test suite:

```bash
python3 -m pytest -v
```

**Current regression baseline:**

```text
333 passed
1 warning
```

The current warning originates from a Starlette/httpx deprecation in the installed testing dependency stack. It does not currently cause test failures.

The test suite covers:

- API behavior
- API configuration
- Database persistence
- Email parsing
- Authentication analysis
- Identity analysis
- Participant analysis
- Infrastructure analysis
- Detection rules
- Risk scoring
- Detection engine behavior
- SIEM event normalization
- SIEM event adaptation
- SIEM integration management
- Splunk integration
- Elastic integration
- Wazuh integration
- Application SIEM configuration
- Behavioral communication anomaly detection
- Historical behavioral analysis
- Historical recipient frequency analysis
- Historical recipient co-occurrence analysis
- Historical recipient role analysis
- Message content anomaly detection
- Historical subject similarity analysis
- Historical body similarity analysis
- Historical body-length anomaly detection
- Structured detection indicators

---

## Development Validation

Before committing changes, the project can be validated with:

```bash
python3 -m pytest -v
```

Check staged changes for whitespace errors:

```bash
git diff --cached --check
```

The project follows incremental development with focused tests followed by full regression testing before commits.

---

## Roadmap

| Item | Status |
|---|---|
| Documentation | ✅ |
| Python project foundation | ✅ |
| Email parser | ✅ |
| Header extraction / normalization | ✅ |
| Identity analysis | ✅ |
| Conversation baseline | ✅ |
| BEC-001 Lookalike Domain | ✅ |
| BEC-002 Reply-To Mismatch | ✅ |
| BEC-003 Participant Anomaly | ✅ |
| BEC-004 Authentication Anomaly | ✅ |
| BEC-005 Infrastructure Anomaly | ✅ |
| BEC-006 Conversation Hijacking | ✅ |
| BEC-007 Behavioral Anomaly | ⏳ Expanding |
| BEC-008 Message Content Anomaly | ✅ |
| Structured detection indicators | ✅ |
| FastAPI | ✅ |
| PostgreSQL | ✅ |
| Docker / Docker Compose | ✅ |
| SIEM event model | ✅ |
| SIEM event adapter | ✅ |
| SIEM integration contract | ✅ |
| SIEM integration manager | ✅ |
| Splunk integration | ✅ |
| Elastic integration | ✅ |
| Wazuh integration | ✅ |
| Application SIEM service | ✅ |
| SIEM integration into analysis workflow | ✅ |
| Application SIEM configuration | ✅ |
| Behavioral detection expansion | ⏳ |
| Content detection expansion | ⏳ |
| ML anomaly detection | ⏳ |

> BEC-007 has an operational deterministic implementation, but behavioral detection expansion remains in progress as additional historical communication signals are added and validated.

> BEC-008 has an operational deterministic implementation covering subject similarity, body similarity, and body-length anomalies. More advanced semantic and attachment-aware content analysis remains future work.

---

## Future Development

Potential future capabilities include:

- Microsoft Graph integration
- Gmail API integration
- IMAP collection
- Automated mailbox monitoring
- Conversation graph visualization
- Sender reputation analysis
- Domain age analysis
- WHOIS/RDAP enrichment
- Threat-intelligence enrichment
- Additional email-specific indicators
- Expanded behavioral detection
- Expanded semantic content analysis
- Attachment-aware content analysis
- Machine-learning anomaly detection
  - Isolation Forest
  - Local Outlier Factor
  - One-Class SVM
  - Autoencoder-based behavioral detection
- Analyst feedback loops
- Case management
- Expanded SIEM dashboards and detection workflows

---

## Research Direction

A future experimental component will investigate whether unsupervised machine learning can identify abnormal email communication behavior without requiring labeled attack datasets.

**Potential features include:**

- `sender_frequency`
- `recipient_frequency`
- `sending_hour`
- `response_time`
- `participant_count`
- `subject_similarity`
- `body_similarity`
- `body_length`
- `attachment_frequency`
- `sender_infrastructure_frequency`
- `domain_similarity`
- `authentication_results`
- `reply_to_frequency`
- `recipient_cooccurrence_frequency`
- `recipient_role_frequency`

**Candidate models include:**

- Isolation Forest
- Local Outlier Factor
- One-Class SVM
- Autoencoder-based anomaly detection

The ML layer will remain separate from the deterministic detection engine so that the system can compare rule-based, behavioral, and content-based approaches.

---

## Current Architecture

The current application architecture can be summarized as:

```text
                         ┌───────────────────┐
                         │    .eml Message   │
                         └─────────┬─────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │   Email Parser    │
                         └─────────┬─────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │ Analysis Context  │
                         └─────────┬─────────┘
                                   │
                ┌──────────────────┼──────────────────┐
                ▼                  ▼                  ▼
        ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
        │   Identity   │   │Authentication│   │Infrastructure│
        │   Analysis   │   │   Analysis   │   │   Analysis   │
        └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
               │                  │                  │
               └──────────────────┼──────────────────┘
                                  ▼
                         ┌───────────────────┐
                         │ Conversation /    │
                         │ Behavior /        │
                         │ Content Analysis  │
                         └─────────┬─────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │ Detection Engine  │
                         └─────────┬─────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │   Risk Scoring    │
                         └─────────┬─────────┘
                                   │
                         ┌─────────┴─────────┐
                         ▼                   ▼
                ┌────────────────┐   ┌────────────────┐
                │   PostgreSQL   │   │   SIEMService  │
                └────────────────┘   └───────┬────────┘
                                             │
                                             ▼
                                    ┌──────────────────┐
                                    │ Integration      │
                                    │ Manager          │
                                    └────────┬─────────┘
                                             │
                                  ┌──────────┼──────────┐
                                  ▼          ▼          ▼
                               Splunk     Elastic     Wazuh
```

---

## Detection Data Flow

The current detection flow can be summarized as:

```text
                         .eml Message
                              │
                              ▼
                         EmailParser
                              │
                              ▼
                     Normalized Email Data
                              │
                              ▼
                      DetectionContext
                              │
             ┌────────────────┼────────────────┐
             ▼                ▼                ▼
          Identity       Authentication   Infrastructure
             │                │                │
             └────────────────┼────────────────┘
                              │
                              ▼
                  Conversation / Participants
                              │
                              ▼
                 Historical Behavioral Data
                              │
                              ▼
                  Historical Content Data
                              │
                              ▼
                     Detection Rules
                              │
                              ▼
                    DetectionResult
                              │
                              ▼
                       RiskScorer
                              │
                              ▼
                    Structured Result
                              │
             ┌────────────────┼────────────────┐
             ▼                ▼                ▼
             API          PostgreSQL          SIEM
```

This separation allows the detection rules to generate explainable evidence while downstream systems determine how that evidence is persisted, displayed, or forwarded.

---

## Limitations

The current MVP has several limitations:

- Detection quality depends on the quality of the supplied baseline.
- Historical behavioral detection requires sufficient historical observations.
- Historical content detection requires sufficient qualifying subject/body observations.
- Deterministic text similarity does not provide semantic understanding.
- Subject and body similarity can produce false positives when legitimate communication changes substantially.
- A declared email timezone offset does not establish physical sender location.
- SPF, DKIM, and DMARC analysis depends on authentication information available in the analyzed message.
- Infrastructure analysis is currently based on observed hosts and IP addresses.
- Sender infrastructure reputation is not currently implemented.
- Attachments are currently outside the scope of BEC-008.
- Machine-learning-based anomaly detection has not yet been integrated into the production detection path.
- Historical baseline poisoning is a potential risk if untrusted observations are introduced into the baseline.
- Detection scores are explainable indicators, not definitive proof of compromise.

These limitations are expected to be addressed incrementally as the project evolves.

---

## Security Considerations

Because the system analyzes potentially sensitive email communications, deployments should consider:

- Secure storage of email data
- Database access controls
- Encryption in transit
- Secret management
- SIEM credential protection
- Access logging
- Data retention policies
- Privacy requirements
- Historical baseline integrity
- Protection against baseline poisoning
- Controlled access to investigation results

> The system should be deployed only in environments where the organization has appropriate authorization to inspect the analyzed communications.

---

## Disclaimer

This project is intended for defensive security research, education, authorized security testing, and SOC detection engineering.

**Only analyze email communications for which appropriate authorization has been obtained.**

---

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for the full license text.

---

## Author

**Allen Ace**
SOC Analyst | Threat Hunter | Detection Engineer

*Detect • Investigate • Respond • Defend*