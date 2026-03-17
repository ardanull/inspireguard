# InspireGuard

<p align="center">
  <strong>Enterprise-grade SOC platform for real-time threat detection, incident correlation, analyst workflows, and scalable security operations.</strong>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.11+-blue.svg">
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-API-green.svg">
  <img alt="PostgreSQL" src="https://img.shields.io/badge/PostgreSQL-Database-blue.svg">
  <img alt="Redis" src="https://img.shields.io/badge/Redis-PubSub-red.svg">
  <img alt="Celery" src="https://img.shields.io/badge/Celery-Background%20Jobs-brightgreen.svg">
  <img alt="Kubernetes" src="https://img.shields.io/badge/Kubernetes-Orchestration-326ce5.svg">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-yellow.svg">
</p>

---

## Overview

**InspireGuard** is a product-oriented Security Operations Center (SOC) platform designed to model how modern defensive security systems operate in real environments.

Rather than acting as a simple IDS or alert generator, InspireGuard is built around the full lifecycle of security operations:

- collecting telemetry from multiple sources
- detecting suspicious activity
- correlating alerts into incidents
- enriching findings with threat intelligence
- supporting analyst investigation workflows
- managing cases, SLA policies, and evidence
- enabling secure, scalable, production-style deployment

This project combines **cybersecurity engineering**, **detection engineering**, **backend architecture**, **distributed systems**, and **security platform design** into a single enterprise-style platform.

---

## Why InspireGuard?

Most security projects stop at packet capture, log parsing, or simple alerting.

InspireGuard was built to go further.

The goal of this platform is to simulate the architectural depth of a real SOC product by bringing together:

- real-time detection
- incident correlation
- case management
- secure agent communication
- rule simulation
- tenant-aware persistence
- live streaming
- deployment readiness
- observability

InspireGuard is designed to feel less like a demo and more like the foundation of a serious defensive security product.

---

## Core Capabilities

### Detection & Telemetry
- Real-time threat detection and alert generation
- Multi-agent collector architecture
- PCAP and live network analysis support
- Suricata EVE JSON ingestion
- Zeek JSON/log ingestion
- Threat intelligence enrichment pipeline

### Detection Engineering
- Sigma-like rule engine
- Rule registry and versioning
- Rule promotion workflow
- Sigma parser and simulation lab
- Detection testing and rule experimentation

### Incident & Analyst Operations
- Incident correlation and enrichment
- Analyst workflow and triage lifecycle
- Case management
- SLA policy handling
- Evidence locker
- Investigation notes and operational context

### Identity & Access
- RBAC-based authorization
- Login and authentication system
- OIDC-ready SSO integration layer
- SAML-ready SSO integration layer
- Tenant-aware security boundaries

### Secure Platform Architecture
- mTLS PKI / CA-backed agent trust model
- Certificate issuance and revocation support
- PostgreSQL-backed persistence
- Row-level tenant isolation foundations
- Redis pub/sub distributed live alert fanout
- WebSocket live alert streaming

### Deployment & Operations
- Docker-based local deployment
- Kubernetes-ready manifests
- Helm chart support
- Observability-ready architecture
- Background jobs with Celery
- Production-oriented service layout

---

## Architecture

InspireGuard is designed as a modular platform composed of multiple subsystems:

```text
                        +----------------------+
                        |   OIDC / SAML IdP    |
                        +----------+-----------+
                                   |
                                   v
+-----------+      +-----------------------------+      +------------------+
| Analysts  | ---> |      Web UI / Dashboard     | <--> |  WebSocket Stream |
+-----------+      +---------------+-------------+      +------------------+
                                   |
                                   v
                        +-------------------------+
                        |      FastAPI Backend    |
                        |  Auth / RBAC / Cases    |
                        |  Incidents / Rules      |
                        +----+--------+-----------+
                             |        |
                +------------+        +-------------------+
                |                                     |
                v                                     v
     +----------------------+              +----------------------+
     | PostgreSQL           |              | Redis Pub/Sub        |
     | tenants, incidents,  |              | live fanout, cache,  |
     | cases, evidence,     |              | async messaging      |
     | rules, audit logs    |              +----------------------+
     +----------------------+                         |
                                                      v
                                            +----------------------+
                                            | Celery Workers       |
                                            | enrichment, SLA,     |
                                            | stale checks, sync   |
                                            +----------------------+

                +--------------------------------------------------+
                |        Ingestion / Detection / Collectors         |
                +--------------------------------------------------+
                | Agents | Live Sniffing | PCAP | Suricata | Zeek |
                +--------------------------------------------------+
