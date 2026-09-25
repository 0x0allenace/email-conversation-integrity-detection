# System Architecture

## Overview

Email Conversation Integrity Detection is a layered Blue Team detection engine designed to analyze email messages for indicators of Business Email Compromise (BEC), sender impersonation, conversation manipulation, and suspicious communication behavior.

The architecture separates email parsing, identity analysis, authentication analysis, infrastructure analysis, detection logic, risk scoring, persistence, and SIEM integration.

The system is designed to remain explainable and extensible as additional detection and behavioral analysis capabilities are introduced.

---

## High-Level Architecture

```text
                         .eml Email
                              │
                              ▼
                    ┌──────────────────┐
                    │   Email Parser   │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Header Extraction│
                    │  & Normalization │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
       ┌────────────┐ ┌──────────────┐ ┌──────────────┐
       │  Identity  │ │Authentication│ │Infrastructure│
       │  Analysis  │ │   Analysis   │ │   Analysis   │
       └─────┬──────┘ └──────┬───────┘ └──────┬───────┘
             │               │                │
             └───────────────┼────────────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Detection Engine │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │   Risk Scoring   │
                    └────────┬─────────┘
                             │
                  ┌──────────┴──────────┐
                  │                     │
                  ▼                     ▼
          ┌──────────────┐      ┌────────────────┐
          │  PostgreSQL  │      │   SIEM Service │
          └──────────────┘      └───────┬────────┘
                                        │
                                        ▼
                               ┌─────────────────┐
                               │ Integration     │
                               │ Manager         │
                               └───────┬─────────┘
                                       │
                             ┌─────────┼─────────┐
                             ▼         ▼         ▼
                          Splunk    Elastic    Wazuh
```

---

## Application Layers

### API Layer

The FastAPI application provides the external interface for submitting emails for analysis and retrieving persisted analyses.

Current endpoints include:

- `GET /health`
- `GET /ready`
- `POST /analyze`
- `GET /analyses`
- `GET /analyses/{id}`

The API delegates analysis to the application service layer.

### Service Layer

`AnalysisService` provides the application-level workflow between the API, detection engine, database repository, and optional SIEM service.

The service:

1. Receives analysis parameters.
2. Invokes the detection engine.
3. Persists analysis results when a database session is provided.
4. Dispatches matched detection results to the configured SIEM service when enabled.

### Email Parser

The parser extracts and normalizes information from `.eml` messages.

The parser provides the structured email information required by downstream analysis components.

Relevant information includes:

- Message ID
- Subject
- Sender
- Recipients
- Reply-To
- Headers
- Authentication-related headers
- Received headers
- Message body information

### Identity Analysis

The identity layer evaluates sender identity information against a supplied baseline.

It supports detection of inconsistencies involving:

- Sender email address
- Sender domain
- Display name
- Known sender identity
- Lookalike domains

### Authentication Analysis

The authentication layer evaluates authentication information available within the analyzed message.

The current implementation considers:

- SPF
- DKIM
- DMARC

The results are passed to the detection engine as structured analysis data.

### Infrastructure Analysis

The infrastructure layer evaluates sender infrastructure against known infrastructure.

**Current indicators include:**

- Sending host
- Sending IP address

The current implementation focuses on previously unseen infrastructure.

**Future enrichment may include:**

- ASN
- Geographic information
- Reverse DNS
- Infrastructure reputation

### Conversation Analysis

Conversation-related analysis uses known participants and conversation context to identify inconsistencies within an established communication relationship.

This includes:

- Known participants
- Unexpected participants
- Thread-related indicators
- Sender identity changes
- Conversation hijacking indicators

The quality of the supplied baseline affects the accuracy of participant-based detections.

### Detection Engine

The detection engine coordinates the individual detection rules and produces structured detection results.

**Current detection rules include:**

- BEC-001 — Lookalike Domain
- BEC-002 — Reply-To Mismatch
- BEC-003 — Thread Participant Anomaly
- BEC-004 — Authentication Anomaly
- BEC-005 — Sender Infrastructure Anomaly
- BEC-006 — Conversation Hijacking
- BEC-007 — Behavioral Communication Anomaly

Each detection produces structured information including:

- Rule ID
- Rule name
- Severity
- Match status
- Risk score
- Indicators
- Details

### Risk Scoring

Risk scoring is performed after detection analysis.

Each detection rule contributes an explainable risk score based on observable indicators. Individual detection scores are capped at 100.

The persisted analysis also records the combined risk score from matched detections.

Risk scoring is intended to support investigation rather than replace analyst judgment.

### Database Layer

PostgreSQL provides persistence for completed analyses.

The current database model contains:

- `analyses`
- `detections`

The analysis record stores the overall analysis result, while individual detection records preserve the rule-level results.

SQLAlchemy is used as the ORM layer.

---

## SIEM Architecture

The SIEM layer separates detection logic from SIEM-specific implementation.

```text
DetectionResult
      │
      ▼
SIEMEventAdapter
      │
      ▼
SIEMEvent
      │
      ▼
SIEMService
      │
      ▼
SIEMIntegrationManager
      │
      ├───────────┬───────────┐
      ▼           ▼           ▼
   Splunk      Elastic      Wazuh
```

### SIEM Event

`SIEMEvent` provides a normalized representation of a detection event.

The event can contain:

- Event type
- Timestamp
- Message ID
- Sender information
- Recipient information
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
- Source
- Schema version

### SIEM Service

`SIEMService` converts detection results into normalized SIEM events and dispatches them through the configured SIEM integration manager.

The service allows the detection engine to remain independent of the destination SIEM platform.

### SIEM Integration Manager

`SIEMIntegrationManager` maintains the registered SIEM integrations.

It supports:

- Registering integrations
- Retrieving integrations
- Listing integrations
- Sending events to one integration
- Broadcasting events to registered integrations

### SIEM Provider Integrations

The current implementation supports:

**Splunk**
Uses Splunk HTTP Event Collector (HEC).
Authentication: HEC token

**Elastic**
Supports:
- API key authentication
- Basic authentication

**Wazuh**
Supports:
- Username/password authentication

---

## Configuration

Application-level SIEM configuration is controlled using environment variables.

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

> Secrets should not be committed to source control.

---

## Container Architecture

Docker Compose is used to run the application and PostgreSQL environment.

```text
             Docker Compose
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
   ECID API             PostgreSQL
   Container             Container
        │                   │
        └─────────┬─────────┘
                  │
             Application
```

External SIEM platforms can be configured through the application environment.

---

## Design Principles

The architecture follows these principles:

**Separation of Concerns**
Parsing, analysis, detection, scoring, persistence, and SIEM integration remain separate components.

**Explainability**
Detection results expose the indicators and details that contributed to a detection.

**Extensibility**
Additional detection rules and SIEM integrations can be added without redesigning the entire application.

**Defensive Design**
The system is designed for authorized security analysis and controlled environments.

**Deterministic First**
Deterministic detection rules provide the foundation before introducing machine-learning-based behavioral analysis.
