# Technical Implementation Guide
## SIEM Log Analysis with LLM Integration

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     SIEM Log Analysis Pipeline                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    │
│  │  Data Input  │───▶│  Processing  │───▶│  Analysis    │    │
│  │   (100Kev)   │    │   (Parse,    │    │  (Stat+LLM)  │    │
│  │   CSV        │    │   Enrich)    │    │              │    │
│  └──────────────┘    └──────────────┘    └──────────────┘    │
│                                                    │           │
│                                                    ▼           │
│                          ┌─────────────────────────────────┐  │
│                          │   Threat Detection Engine       │  │
│                          ├─────────────────────────────────┤  │
│                          │ • Threat Classification (ML)    │  │
│                          │ • Anomaly Detection (Stats)     │  │
│                          │ • Vulnerability Ranking (LLM)   │  │
│                          │ • Correlation Analysis          │  │
│                          └─────────────────────────────────┘  │
│                                                    │           │
│                                                    ▼           │
│                    ┌────────────────────────────────────────┐ │
│                    │      Multi-Output Generation           │ │
│                    ├────────────────────────────────────────┤ │
│                    │ • Statistical Reports                  │ │
│                    │ • Visual Analytics (11 types)          │ │
│                    │ • Executive Summary                    │ │
│                    │ • Actionable Recommendations           │ │
│                    └────────────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Data Loading & Parsing

### CSV Processing
```python
import csv
from pathlib import Path
from datetime import datetime

# 1. Load CSV
with Path('advanced_siem.csv').open(newline='', encoding='utf-8') as f:
    rows = list(csv.DictReader(f))

# 2. Enrich data
for row in rows:
    # Parse timestamp
    row['parsed_timestamp'] = datetime.strptime(
        row['timestamp'], 
        '%Y-%m-%d %H:%M:%S'
    )
    
    # Parse embedded dictionaries
    row['advanced_metadata_dict'] = parse_mapping(row['advanced_metadata'])
    row['behavioral_analytics_dict'] = parse_mapping(row['behavioral_analytics'])

# 3. Extract schema
column_names = list(rows[0].keys())
```

### Schema Analysis
```
Available Columns (20):
├── timestamp        (datetime)
├── event_type       (string: ids_alert, malware, ai, cloud, endpoint, iot, firewall)
├── source           (string: vendor/product name)
├── severity         (category: emergency, critical, high, medium, low, info)
├── user             (string: username, optional)
├── action           (string: specific event action)
├── src_ip           (string: source IP address)
├── alert_type       (string: specific alert classification)
├── device_type      (string: IoT device types)
├── cloud_service    (string: cloud provider)
├── model_id         (string: AI model identifier)
├── category         (string: IDS alert category)
├── protocol         (string: network protocol)
├── advanced_metadata      (dict: risk_score, confidence, geo_location)
└── behavioral_analytics   (dict: baseline_deviation, entropy, anomaly flags)
```

---

## Phase 2: Statistical Analysis

### Fundamental Statistics

**Event Distribution**
```python
event_type_counts = Counter(row['event_type'] for row in rows)
# Output: IDS=12.5K, AI=12K, Cloud=12K, Endpoint=12K, ...

severity_counts = Counter(row['severity'] for row in rows)
# Output: Critical=18.5K, High=19.7K, Medium=24K, Low=21.2K, ...
```

**Descriptive Statistics**
```python
from statistics import mean, stdev, median

risk_scores = [float(r['advanced_metadata_dict'].get('risk_score')) 
               for r in rows if r['advanced_metadata_dict'].get('risk_score')]

stats = {
    'mean': mean(risk_scores),      # 50.0
    'stdev': stdev(risk_scores),     # ~29
    'min': min(risk_scores),         # 0.0
    'max': max(risk_scores),         # 100.0
    'median': median(risk_scores)    # 50.5
}
```

### Correlation Analysis

**Pearson Correlation Coefficient**
```python
def pearson_correlation(x_list, y_list):
    """
    Calculate Pearson r correlation coefficient
    Formula: r = Σ((x - x_mean) * (y - y_mean)) / √(Σ(x-x_mean)² * Σ(y-y_mean)²)
    Range: -1.0 (inverse) to +1.0 (perfect positive)
    """
    n = len(x_list)
    mean_x = sum(x_list) / n
    mean_y = sum(y_list) / n
    
    numerator = sum((x_list[i] - mean_x) * (y_list[i] - mean_y) for i in range(n))
    denom_x = (sum((x - mean_x) ** 2 for x in x_list)) ** 0.5
    denom_y = (sum((y - mean_y) ** 2 for y in y_list)) ** 0.5
    
    if denom_x * denom_y == 0:
        return 0
    return numerator / (denom_x * denom_y)

# Apply to risk, confidence, severity
risk_list = [float(r['advanced_metadata_dict'].get('risk_score')) for r in rows]
conf_list = [float(r['advanced_metadata_dict'].get('confidence')) for r in rows]
sev_list = [severity_numeric[r['severity'].lower()] for r in rows]

r_risk_conf = pearson_correlation(risk_list, conf_list)  # -0.003
r_risk_sev = pearson_correlation(risk_list, sev_list)    # 0.002
r_conf_sev = pearson_correlation(conf_list, sev_list)    # 0.001
```

**Interpretation**: Near-zero correlations indicate independence, suggesting:
- Risk and confidence come from different sources
- Severity is assigned independently of risk metrics
- Multi-source SIEM data

### Anomaly Detection (Z-Score)

```python
from statistics import mean

def calculate_z_score(value, population_list):
    """
    Z-Score: (value - population_mean) / population_stdev
    Interpretation:
    - Z > 2.0: Significant outlier (95% confidence)
    - Z > 3.0: Extreme outlier (99.7% confidence)
    """
    mean_val = mean(population_list)
    variance = sum((x - mean_val) ** 2 for x in population_list) / len(population_list)
    std_dev = variance ** 0.5
    
    if std_dev == 0:
        return 0
    return (value - mean_val) / std_dev

# Apply to source IP event counts
events_per_source = Counter(row['src_ip'] for row in rows)
z_scores = {
    source: calculate_z_score(count, list(events_per_source.values()))
    for source, count in events_per_source.items()
}

anomalies = [(source, count, z) for source, (count, z) in ... if z > 2.0]
# Result: 1 anomaly found (z=223.15, 50,201 events from unknown)
```

---

## Phase 3: Threat Detection

### Threat Score Calculation

```python
def calculate_threat_score(row):
    """
    Multi-factor threat assessment
    Scale: 0-20 (higher = more malicious)
    """
    threat_score = 0
    
    # Factor 1: Severity weighting (0-10)
    severity_weights = {
        'emergency': 10,
        'critical': 8,
        'high': 6,
        'medium': 4,
        'low': 2,
        'info': 1
    }
    threat_score += severity_weights.get(row['severity'].lower(), 0)
    
    # Factor 2: Risk score contribution (0-5)
    risk = float(row['advanced_metadata_dict'].get('risk_score')) or 0
    threat_score += min(risk / 20, 5)  # Scale 0-100 to 0-5
    
    # Factor 3: Keyword matching (0-5)
    malicious_keywords = [
        'exploit', 'injection', 'backdoor', 'ransomware', 'malware',
        'phishing', 'credential', 'crypto', 'unauthorized', 'breach'
    ]
    event_action = (row['event_type'] + ' ' + (row['action'] or '')).lower()
    matches = sum(1 for kw in malicious_keywords if kw in event_action)
    threat_score += min(matches * 0.5, 5)
    
    return threat_score

# Classification thresholds
MALICIOUS_THRESHOLD = 12    # High confidence threat
SUSPICIOUS_THRESHOLD = 7    # Requires investigation
# Below 7: Legitimate activity
```

### Classification Results

```
Total Events: 100,000

MALICIOUS (score ≥ 12):
  22,078 events (22.08%)
  → Confirmed threats requiring immediate action
  
SUSPICIOUS (7 ≤ score < 12):
  60,031 events (60.03%)
  → Potential threats requiring investigation
  
LEGITIMATE (score < 7):
  17,891 events (17.89%)
  → Normal activity, baseline traffic
```

---

## Phase 4: Vulnerability Assessment

### CVSS Scoring

```python
def estimate_cvss_score(vulnerability_type, exploitability, impact):
    """
    CVSS v3.1 Base Score Calculation
    Formula: CVSS = min(1.08 * (av + pr + ui) * (c + i + a), 10.0)
    
    where:
    - av: Attack Vector (0.85-1.0)
    - pr: Privileges Required (0.62-0.68)
    - ui: User Interaction (0.85-0.62)
    - c: Confidentiality Impact (0.22-0.56)
    - i: Integrity Impact (0.22-0.56)
    - a: Availability Impact (0.22-0.56)
    """
    
    # Simplified estimation for demonstration
    cvss_estimates = {
        'Credential Exposure': 8.2,
        'Command Injection': 9.1,
        'Privilege Escalation': 8.8,
        'SQL Injection': 8.6,
        'API Bypass': 7.8,
        'XSS': 6.1,
        'Unencrypted_Channel': 6.5,
    }
    
    return cvss_estimates.get(vulnerability_type, 5.0)

# Severity mapping
def cvss_to_severity(score):
    """
    CVSS Score → Severity Classification
    """
    if score >= 9.0:
        return 'CRITICAL'
    elif score >= 7.0:
        return 'HIGH'
    elif score >= 4.0:
        return 'MEDIUM'
    else:
        return 'LOW'
```

### Vulnerability Detection

```python
# Extract high/critical severity events
vulnerable_events = [row for row in rows 
                     if row['severity'].lower() in ['critical', 'high']]

# Categorize by type
vuln_keywords = {
    'credential': 'Credential Exposure',
    'injection': 'Injection Vulnerability',
    'sql': 'SQL Injection',
    'xss': 'Cross-Site Scripting',
    'rce': 'Remote Code Execution',
    'privilege': 'Privilege Escalation',
    'api': 'API Vulnerability',
}

vuln_by_type = defaultdict(list)
for row in vulnerable_events:
    action = row['action'].lower() if row['action'] else ''
    for keyword, vuln_type in vuln_keywords.items():
        if keyword in action:
            vuln_by_type[vuln_type].append(row)

# Result counts:
# Injection Vulnerability:  1,730 instances
# API Vulnerability:        1,143 instances
# Credential Exposure:      ~900 instances
```

---

## Phase 5: LLM Integration

### API Setup

```python
import os
import json
from urllib.request import urlopen, Request

# Configuration
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', 'your-key')

def call_gemini(prompt, max_tokens=1024):
    """
    Call Google Gemini API
    """
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": GEMINI_API_KEY
    }
    data = json.dumps({
        "system_instruction": {
            "parts": [{"text": "Return a single valid JSON object only."}]
        },
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "maxOutputTokens": max_tokens,
            "temperature": 0.3,
            "responseMimeType": "application/json"
        }
    }).encode('utf-8')
    
    req = Request(url, data=data, headers=headers, method='POST')
    try:
        with urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode('utf-8'))
            return result['candidates'][0]['content']['parts'][0]['text']
    except Exception as e:
        print(f"API error: {e}")
        return None
```

### Threat Analysis Prompt Engineering

```python
def build_threat_analysis_prompt(malicious_events):
    """
    Build comprehensive threat analysis prompt for LLM
    """
    events_text = "\n".join([
        f"Event {i+1}: Type={e['event_type']}, "
        f"Severity={e['severity']}, "
        f"Action={e['action']}, "
        f"Risk={e['advanced_metadata_dict'].get('risk_score', 'N/A')}"
        for i, e in enumerate(malicious_events[:5])
    ])
    
    prompt = f"""
    Analyze these security events and identify threat patterns:
    
    {events_text}
    
    For each event, provide:
    1. Threat Classification (Malicious/Suspicious/Legitimate)
    2. Attack Pattern (if applicable)
    3. Confidence level (0-100)
    4. Recommended action
    
    Format as JSON with keys: classifications, patterns, risk_level, urgent_actions
    """
    
    return prompt
```

### LLM Response Parsing

```python
try:
    # Try to parse structured JSON response
    threat_json = json.loads(llm_response)
    
    threat_patterns = threat_json.get('patterns', [])
    risk_level = threat_json.get('risk_level', 'MEDIUM')
    confidence = threat_json.get('confidence', 0)
    
except json.JSONDecodeError:
    # Fallback: extract text insights
    print(f"LLM Response (text format): {llm_response}")
    
    # Pattern matching for key indicators
    if 'credential' in llm_response.lower():
        threat_patterns.append('Credential theft')
    if 'lateral' in llm_response.lower():
        threat_patterns.append('Lateral movement')
    if 'ransomware' in llm_response.lower():
        threat_patterns.append('Ransomware deployment')
```

---

## Phase 6: Correlation Analysis

### Event Co-Occurrence Matrix

```python
from collections import defaultdict

# Track events by source and time
events_by_source_time = defaultdict(lambda: defaultdict(list))

for row in rows:
    source = row['src_ip'] if row['src_ip'] else 'unknown'
    timestamp = row['parsed_timestamp'].strftime('%Y-%m-%d %H:%M')
    event_type = row['event_type']
    
    events_by_source_time[f"{source}_{timestamp}"][timestamp].append(event_type)

# Calculate co-occurrences
event_pairs = defaultdict(int)

for source_time_key, time_dict in events_by_source_time.items():
    for timestamp, event_list in time_dict.items():
        for i, event1 in enumerate(event_list):
            for event2 in event_list[i+1:]:
                pair = tuple(sorted([event1, event2]))
                event_pairs[pair] += 1

# Top pairs indicate attack chains:
# AI + Cloud: 574 occurrences → Multi-layer compromise
# AI + IoT: 555 occurrences → Device network infection
# Cloud + Endpoint: 547 occurrences → Infrastructure penetration
```

### Risk Matrix Calculation

```python
def build_risk_matrix(rows):
    """
    Create source → severity → count matrix
    """
    risk_matrix = defaultdict(lambda: defaultdict(int))
    
    for row in rows:
        source = row['src_ip'] or 'unknown'
        severity = row['severity'].lower()
        
        risk_matrix[source][severity] += 1
    
    # Calculate average risk per source
    source_metrics = {}
    for source, severities in risk_matrix.items():
        total_events = sum(severities.values())
        critical_count = severities['critical'] + severities.get('emergency', 0)
        avg_risk = critical_count / total_events if total_events > 0 else 0
        
        source_metrics[source] = {
            'total_events': total_events,
            'critical_pct': avg_risk * 100,
            'severity_breakdown': dict(severities)
        }
    
    return source_metrics
```

---

## Phase 7: Visualization Generation

### Text-Based Charts (Fallback)

```python
def text_bar_chart(title, data_dict, max_width=50):
    """
    ASCII bar chart for terminal output
    """
    print(f"\n{title}")
    print("=" * len(title))
    
    max_value = max(data_dict.values()) if data_dict.values() else 1
    
    for label, value in sorted(data_dict.items(), 
                               key=lambda x: x[1], 
                               reverse=True)[:10]:
        bar_width = int((value / max_value) * max_width) if max_value > 0 else 0
        bar = "█" * bar_width
        print(f"{label:<25} [{bar:<{max_width}}] {value:>6,}")

# Usage
event_dist = dict(event_type_counts.most_common(15))
text_bar_chart("Top 15 Event Types", event_dist)
```

### Python Matplotlib Integration (Optional)

```python
import matplotlib.pyplot as plt
import numpy as np

def plot_threat_distribution(threat_classification):
    """
    Pie chart of threat categories
    """
    labels = ['Malicious', 'Suspicious', 'Legitimate']
    sizes = [
        len(threat_classification['MALICIOUS']),
        len(threat_classification['SUSPICIOUS']),
        len(threat_classification['LEGITIMATE'])
    ]
    colors = ['#ff4444', '#ffaa00', '#44ff44']
    
    fig, ax = plt.subplots(figsize=(10, 8))
    ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
           startangle=90)
    ax.set_title('Security Event Classification')
    plt.savefig('threat_distribution.png', dpi=300, bbox_inches='tight')
    plt.show()
```

---

## Phase 8: Report Generation

### Executive Summary Template

```python
def generate_executive_report(analysis_data):
    """
    Generate markdown report with findings
    """
    
    report = f"""
# EXECUTIVE THREAT INTELLIGENCE REPORT

Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Analysis Period: {analysis_data['min_timestamp']} to {analysis_data['max_timestamp']}
Total Events: {len(rows):,}

## Key Findings

### Threat Level: {analysis_data['threat_level']}

- **Critical/High Severity**: {analysis_data['critical_count']:,} ({analysis_data['critical_pct']:.2f}%)
- **Malicious Events**: {analysis_data['malicious_count']:,} ({analysis_data['malicious_pct']:.2f}%)
- **Vulnerable Systems**: {analysis_data['vulnerable_count']:,}

## Immediate Actions

1. Isolate {analysis_data['anomalous_sources']} anomalous source IP(s)
2. Rotate credentials for affected accounts
3. Enable enhanced logging and monitoring
4. Escalate to executive leadership

## Remediation Timeline

- **0-24 hours**: Containment actions
- **1-7 days**: Eradication planning
- **2-4 weeks**: System hardening
- **1-6 months**: Strategic improvements
"""
    
    return report
```

---

## Data Flow Summary

```
┌─────────────────────────────────────────────────────────┐
│ Input: advanced_siem.csv (100,000 events)              │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│ Step 1: Parse & Enrich                                 │
│ - Load CSV                                             │
│ - Parse timestamps                                     │
│ - Extract metadata dictionaries                        │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│ Step 2: Statistical Analysis                           │
│ - Descriptive statistics (mean, stdev, etc.)          │
│ - Pearson correlations                                │
│ - Z-score anomaly detection                           │
│ - Co-occurrence matrices                              │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│ Step 3: Threat Detection                               │
│ - Calculate threat scores                             │
│ - Classify malicious/suspicious/legitimate            │
│ - Extract high-risk patterns                          │
│ - Identify anomalies                                  │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│ Step 4: Vulnerability Assessment                       │
│ - Identify vulnerable events                          │
│ - Estimate CVSS scores                                │
│ - Categorize by type                                  │
│ - Rank by impact                                      │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│ Step 5: LLM Analysis                                   │
│ - Threat pattern recognition                          │
│ - Vulnerability prioritization                        │
│ - Correlation interpretation                          │
│ - Attack campaign identification                      │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│ Step 6: Visualization & Reporting                      │
│ - Generate 11 chart types                             │
│ - Create executive summary                            │
│ - Compile action items                                │
│ - Export findings                                     │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│ Outputs:                                               │
│ - ANALYSIS_REPORT.md (comprehensive findings)         │
│ - README.md (quick reference)                         │
│ - analysis.ipynb (executable notebook)                │
│ - Threat intelligence (JSON)                          │
│ - Visualizations (text + PNG)                         │
│ - CSV exports (malicious events)                      │
└─────────────────────────────────────────────────────────┘
```

---

## Performance Optimization

### Memory Usage
```
100K events × ~2KB per event = ~200MB
Metadata parsing: +50MB  
Correlation matrices: +30MB
Total: ~300-400MB RAM required
```

### CPU Optimization
- Single-threaded analysis (pandas-free)
- Counter-based aggregation (O(n))
- Early filtering in loops
- Vectorized calculations where possible

### Latency Breakdown
```
Data loading:       2-5 seconds
Parsing:            3-8 seconds
Statistical calc:   5-10 seconds
Threat scoring:     8-15 seconds
Correlations:       15-30 seconds
LLM API calls:      30-120 seconds
Visualization:      5-10 seconds
Report generation:  2-5 seconds
────────────────────────────
Total:              ~1-2 minutes
```

---

## Extension Points

### Custom Threat Rules
```python
# Add domain-specific threat keywords
malicious_keywords.extend([
    'custom_ioc_1',
    'custom_ioc_2',
    'custom_attack_type'
])

# Add severity weightings
severity_weights['custom_level'] = 7
```

### Additional Metrics
```python
# Add custom scoring
custom_score = (risk_score * 0.4 + 
                severity_numeric * 0.3 + 
                confidence_score * 0.3)

threat_classification[custom_score > 0.7].append(row)
```

### Integration Points
- SIEM systems (Splunk, ELK, etc.)
- SOAR platforms (Phantom, Demisto)
- Ticketing systems (Jira, ServiceNow)
- Notification channels (Slack, email)

---

**Technical Documentation Complete**  
**Questions?** Review notebook cells for implementation details.
