# tools.birolbenli.com — expansion roadmap

Architectural rules (non-negotiable):

- All checks are **external / public-perspective** only.
- No SSH, RDP, WinRM, PowerShell remoting, or agent install.
- No target-server credentials collected.
- Prefer public DNS, TCP, TLS, HTTP(S), SMTP, and public internet sources.
- Every results screen keeps an **External Check** notice.
- Preserve existing design language; do not remove or break current tools.
- No aggressive vuln scanning / exploit attempts.

---

## Status legend

| Tag | Meaning |
|-----|---------|
| **SHIPPED** | Live as a dedicated tool slug |
| **COVERED** | Capability already inside another tool (e.g. Exchange HC) |
| **WAVE-1** | Shipping in the current expansion batch |
| **NEXT** | High value, next engineering sprint |
| **LATER** | Needs more design / APIs / time |

---

## Homepage categories (target)

1. Featured  
2. Domain Security  
3. Email authentication  
4. SMTP & mail server  
5. Microsoft Exchange  
6. DNS & domain  
7. SSL / TLS  
8. Web security  
9. IP & network  
10. Security & reconnaissance  
11. Generator tools  

Featured targets (when available): Domain Security Audit, Exchange External Health, Email Security Score, SSL/TLS Analyzer, HTTP Security Headers, IP Intelligence.

---

## 1. Email security

| # | Tool | Status | Notes |
|---|------|--------|-------|
| 1 | MTA-STS Checker | **WAVE-1** | DNS + policy file + score |
| 2 | TLS-RPT Checker | **WAVE-1** | `_smtp._tls` + rua/syntax |
| 3 | BIMI Checker | **WAVE-1** | TXT + logo URL reachability |
| 4 | ARC Checker | **NEXT** | Extend header analyzer |
| 5 | DANE / TLSA Checker | **WAVE-1** | Public TLSA query (no full DNSSEC validation claim) |
| 6 | SMTP TLS Analyzer | **NEXT** | Deepen `smtp` + Exchange SMTP assess |
| 7 | SMTP Certificate Checker | **NEXT** | STARTTLS leaf/chain on :25 |
| 8 | SMTP Banner Analyzer | **COVERED** / **NEXT** | Partial in `smtp`; split UI later |
| 9 | SMTP Authentication Checker | **NEXT** | EHLO AUTH mechs + warnings |
| 10 | Email Security Score | **NEXT** | Orchestrate SPF…DANE + SMTP TLS |
| 11 | Email Deliverability Checker | **COVERED** | Closest: Mail Tester + existing lookups |
| 12 | Open Relay Check | **COVERED** / **NEXT** | Safe probe inside Exchange; standalone later |

## 2. Domain security

| # | Tool | Status |
|---|------|--------|
| 13 | Domain Security Audit | **NEXT** (flagship) |
| 14 | Domain Health Check | **NEXT** |
| 15 | security.txt Checker | **WAVE-1** |

## 3. DNS

| # | Tool | Status |
|---|------|--------|
| 16 | DNSSEC Checker | **NEXT** | DS/DNSKEY presence first; full chain later |
| 17 | DNS Propagation Checker | **NEXT** |
| 18 | DNS TTL Analyzer | **LATER** |
| 19 | DNS Zone Analyzer | **LATER** |
| 20 | SOA Checker | **WAVE-1** |
| 21 | CNAME Checker | **WAVE-1** |
| 22 | DNS Record Comparison | **NEXT** |

## 4. SSL / TLS

| # | Tool | Status |
|---|------|--------|
| 23 | Advanced SSL/TLS Analyzer | **NEXT** | Build on `ssl` + Exchange TLS |
| 24 | Certificate Expiry Checker | **COVERED** | `ssl` bulk checker |
| 25 | Certificate Chain Analyzer | **NEXT** |
| 26 | Certificate Transparency Search | **LATER** | crt.sh / public CT |
| 27 | HSTS Checker | **WAVE-1** |
| 28 | TLS Security Score | **NEXT** |

## 5. Web security

| # | Tool | Status |
|---|------|--------|
| 29 | HTTP Security Headers Analyzer | **WAVE-1** |
| 30 | HTTP Status Checker | **COVERED** | `http` |
| 31 | Redirect Checker | **WAVE-1** |
| 32 | HTTP Response Analyzer | **NEXT** |
| 33 | Cookie Security Checker | **NEXT** |
| 34 | CORS Checker | **LATER** |
| 35 | CDN Detector | **NEXT** |
| 36 | robots.txt Checker | **WAVE-1** |
| 37 | sitemap.xml Checker | **NEXT** |

## 6. Microsoft Exchange / mail server

| # | Tool | Status |
|---|------|--------|
| 38 | Exchange External Health | **SHIPPED** | `exchange` |
| 39 | Exchange Endpoint Checker | **COVERED** | inside `exchange` |
| 40 | Hybrid External Analyzer | **COVERED** | partial / NOT_OBSERVABLE where needed |
| 41 | Autodiscover Checker | **SHIPPED** | `autodiscover` (DNS A/CNAME + SRV + HTTPS) |
| 42 | EWS External Checker | **COVERED** | inside `exchange` |
| 43 | MRSProxy External Checker | **COVERED** | inside `exchange` |
| 44 | Exchange SMTP Health | **COVERED** / **NEXT** | deepen cert/rDNS |

## 7. IP / network

| # | Tool | Status |
|---|------|--------|
| 45 | IP Intelligence | **NEXT** | extend `ip` (ASN/org) |
| 46 | ASN Lookup | **LATER** |
| 47 | BGP Prefix Lookup | **LATER** |
| 48 | IP Reputation | **COVERED** | `blacklist` |
| 49 | Traceroute | **LATER** | often blocked in containers |
| 50 | TCP Traceroute | **LATER** |
| 51 | Ping / Latency | **LATER** | ICMP often blocked |
| 52 | HTTP Connectivity Test | **NEXT** |
| 53 | Port Test | **SHIPPED** | `port` |
| 54 | UDP Connectivity | **LATER** |

## 8. Security / reconnaissance

| # | Tool | Status |
|---|------|--------|
| 55 | Passive Subdomain Discovery | **LATER** | passive sources only |
| 56 | Subdomain Takeover Checker | **LATER** |
| 57 | Well-Known URL Checker | **NEXT** | after security.txt / MTA-STS |
| 58 | Technology Detection | **LATER** |
| 59 | Exposed Service Checker | **LATER** | safe ports only |

## 9. Generators

| # | Tool | Status |
|---|------|--------|
| 60 | SPF Generator | **WAVE-1** |
| 61 | DMARC Generator | **WAVE-1** |
| 62 | MTA-STS Generator | **WAVE-1** |
| 63 | TLS-RPT Generator | **WAVE-1** |
| 64 | CAA Generator | **WAVE-1** |
| 65 | BIMI Generator | **NEXT** |
| 66 | security.txt Generator | **WAVE-1** |

## 10. Platform features

| Feature | Status |
|---------|--------|
| 0–100 scores on scanners | Wave-1 tools + Exchange; expand |
| Severity / pass-warn-fail | Exchange pattern → reuse |
| Remediation + references | Exchange pattern → reuse |
| JSON output | Already via API / `?format=json` |
| Shareable report URL | Mail Tester yes; expand later |
| PDF report | **LATER** |

---

## Delivery waves

### Wave 1 (this batch) — fast external checkers + generators

Ship dedicated slugs built on existing DNS/HTTP helpers.

### Wave 2 — Email Security Score + Domain Security Audit

Orchestrators that call Wave-1 + existing SPF/DKIM/DMARC/MX/SSL/HTTP/blacklist.

### Wave 3 — Deep SMTP/TLS + DNSSEC/propagation + IP intelligence

### Wave 4 — Passive recon, CT search, PDF/shareable reports

---

## Definition of done (per tool)

- External-only implementation  
- TOOLS entry + `/api/<slug>` + homepage placement  
- Results UI with External Check badge  
- TR strings for name/desc  
- Rate limit per tool (`tool:<slug>`)  
- No credentials, no intrusive probes  
