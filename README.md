# Email Conversation Integrity Detection

**Detect • Investigate • Respond**

An open-source Blue Team detection engine designed to identify suspicious email messages that appear to impersonate, clone, or hijack an established business email conversation.

The project focuses on Business Email Compromise (BEC), email impersonation, conversation hijacking, and sender identity anomalies by analyzing email headers, authentication results, sender identity, conversation history, infrastructure, and communication behavior.

---

## Project Status

**Development Stage:** MVP / Active Development

The current implementation provides:

- Email parsing and normalization
- Sender identity analysis
- Conversation participant analysis
- Lookalike-domain detection
- Reply-To mismatch detection
- Thread participant anomaly detection
- SPF/DKIM/DMARC analysis
- Sender infrastructure anomaly detection
- Conversation hijacking analysis
- Deterministic behavioral communication anomaly detection
- Explainable per-rule risk scoring
- FastAPI API
- PostgreSQL persistence
- Docker / Docker Compose deployment
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

**Example:**

| Message | Address |
|---|---|
| Legitimate participant | `John Smith <john@supplier.com>` |
| Suspicious message | `John Smith <john@supp1ier.com>` |

The display name and domain may appear convincing to a human recipient while the underlying identity is different.

The purpose of Email Conversation Integrity Detection is to identify these inconsistencies automatically and provide an explainable risk assessment.

---

## Objectives

1. Parse and normalize email messages.
2. Extract security-relevant email headers.
3. Reconstruct email conversations.
4. Establish known participants within a conversation.
5. Detect sender identity inconsistencies.
6. Detect lookalike domains.
7. Analyze Reply-To and sender relationships.
8. Evaluate SPF, DKIM, and DMARC results where available.
9. Identify suspicious infrastructure changes.
10. Detect abnormal communication behavior.
11. Generate explainable risk scores.
12. Produce SOC-friendly detection results.
13. Integrate detections with SIEM platforms.
14. Provide an extensible foundation for behavioral anomaly detection.

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
git clone <repository-url>
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

> The participant baseline should contain every established participant of the conversation (both `bob@supplier.com` and `alice@company.com` above) — omitting one causes BEC-003 to flag that participant as unexpected.

The API returns:

- Parsed email information
- Sender identity
- Conversation participants
- Authentication results
- Infrastructure information
- Detection results
- Per-rule risk scores

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

The system establishes a baseline from legitimate messages within a conversation, then compares newly received messages against that baseline.

```text
                    Incoming Email
                          │
                          ▼
                   Email Parser
                          │
                          ▼
                 Header Extraction
                          │
                          ▼
              Conversation Reconstruction
                          │
                          ▼
                  Identity Analysis
                          │
          ┌───────────────┼────────────────┐
          ▼               ▼                ▼
      Authentication   Infrastructure   Behavior
          │               │                │
          └───────────────┼────────────────┘
                          ▼
                    Detection Engine
                          │
                          ▼
                     Risk Scoring
                          │
                 ┌────────┴────────┐
                 ▼                 ▼
             Normal            Suspicious
                                   │
                                   ▼
                              SOC Alert
```

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

This detection depends on the quality of the conversation baseline.

### BEC-004 — Authentication Anomaly

Analyzes available authentication results:

- SPF
- DKIM
- DMARC

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

The current rule uses conversation/thread indicators together with sender identity and conversation context.

### BEC-007 — Behavioral Communication Anomaly

Identifies unusual communication behavior compared with an established sender or conversation baseline.

The current MVP includes deterministic time-of-day behavioral analysis. Future versions will expand behavioral analysis using additional communication features and statistical or machine-learning techniques.

---

## Risk Scoring

The detection engine produces an explainable risk score for each detection rule. Scores are derived from observable detection indicators rather than relying on an opaque classification.

```text
Domain mismatch
        +
Authentication failure
        +
Unexpected participant
        ↓
Explainable risk contribution
```

The current scoring implementation assigns rule-specific contributions and caps each individual detection score at 100. The persisted analysis also records the combined risk score of matched detections.

> The numerical score should not be treated as a standalone verdict. Detection results should always be investigated using the underlying indicators and evidence.

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

The detector may identify:

> ⚠ **Suspicious Conversation Participant**
>
> **Known identity:** `bob@supplier.com`
> **Observed identity:** `bob@supp1ier.com`
>
> **Indicators:**
> - Display name matches known participant
> - Domain differs from known participant
> - Domain is visually similar
> - Sender has not previously appeared in the supplied baseline
>
> **Classification:** Potential impersonation
> **Risk:** Determined by the configured detection rules

---

## Project Structure

```text
email-conversation-integrity-detection/
│
├── README.md
├── LICENSE
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
│   ├── parser/
│   └── scoring/
│
├── rules/
│
├── tests/
│
├── samples/
│   ├── legitimate/
│   ├── lookalike-domain/
│   ├── reply-to-manipulation/
│   └── thread-hijacking/
│
├── dashboards/
│
├── integrations/
│   ├── splunk/
│   ├── elastic/
│   └── wazuh/
│
└── scripts/
```

---

## Technology Stack

| Component | Technology |
|---|---|
| Language | Python |
| API | FastAPI |
| Database | PostgreSQL |
| ORM | SQLAlchemy |
| Email Parsing | Python `email` package |
| Authentication Analysis | SPF / DKIM / DMARC header analysis |
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
Layer 5 — Behavioral Analysis
        ↓
Layer 6 — Risk Scoring
        ↓
Layer 7 — SOC Alerting
```

The implementation prioritizes deterministic and explainable detections before introducing machine-learning-based anomaly detection.

---

## Security Design Principles

**Explainability**
Every alert should explain why the message was considered suspicious.

**Evidence First**
Detections should be based on observable email evidence rather than assumptions.

**Least Privilege**
Future integrations should request only the permissions required to inspect and alert on email.

**Safe Testing**
The project uses synthetic emails and controlled laboratory environments.

**Human Verification**
High-impact actions should not be performed automatically solely because a message receives a high risk score.

---

## Testing

The project uses Pytest for automated testing.

Run the complete test suite:

```bash
pytest -q
```

The current regression baseline is:

```text
121 passed
```

A Starlette/httpx deprecation warning may appear depending on the installed dependency versions. It does not currently cause test failures.

---

## Planned SIEM Integrations

The project contains integration directories for future SIEM implementations:

```text
integrations/
├── splunk/
├── elastic/
└── wazuh/
```

**Splunk**

- Detection event ingestion
- Dashboards
- Correlation searches
- Investigation workflows
- Alerting

**Elastic**

- Elasticsearch event ingestion
- Kibana dashboards
- Detection rules
- Investigation workflows

**Wazuh**

- Security event ingestion
- Alert correlation
- SOC monitoring

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
- Machine-learning anomaly detection
  - Isolation Forest
  - Local Outlier Factor
  - One-Class SVM
  - Autoencoder-based behavioral detection
- Analyst feedback loops
- Case management

---

## Research Direction

A future experimental component will investigate whether unsupervised machine learning can identify abnormal email communication behavior without requiring labeled attack datasets.

Potential features include:

- `sender_frequency`
- `recipient_frequency`
- `sending_hour`
- `response_time`
- `participant_count`
- `subject_similarity`
- `body_similarity`
- `attachment_frequency`
- `sender_infrastructure_frequency`
- `domain_similarity`
- `authentication_results`
- `reply_to_frequency`

The ML layer will remain separate from the deterministic detection engine so that the system can compare rule-based and behavioral approaches.

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
| BEC-007 Behavioral Anomaly | ✅ |
| FastAPI | ✅ |
| PostgreSQL | ✅ |
| Docker / Docker Compose | ✅ |
| SIEM integration foundation | 🚧 |
| Splunk integration | ⏳ |
| Elastic integration | ⏳ |
| Wazuh integration | ⏳ |
| Behavioral detection expansion | ⏳ |
| ML anomaly detection | ⏳ |

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