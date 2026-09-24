# Windsurf-AI-Traffic-Interceptor
🛡️ Python + mitmproxy tool for intercepting Windsurf AI traffic in VS Code, extracting AI prompts/responses, and masking sensitive data before secure JSON logging.

# 🛡️ Windsurf AI Traffic Interceptor

A Python-based AI traffic monitoring and security project that intercepts communication between the **Windsurf (Codeium) AI extension in Visual Studio Code** and its backend services.

The tool uses **mitmproxy** to inspect AI-related traffic, extract user prompts and AI responses, automatically mask sensitive information, and store the results in structured JSON files.

> ⚠️ This project is intended only for educational, research, debugging, and authorized security-testing environments.

---

## 📌 Repository

**Repository Name:** `Windsurf-AI-Traffic-Interceptor`

### Description

> 🛡️ Python + mitmproxy tool for intercepting Windsurf AI traffic in VS Code, extracting AI prompts/responses, and masking sensitive data before secure JSON logging.

---

## 🎯 Project Overview

AI coding assistants communicate continuously with cloud-based backend services.

Understanding what information is transmitted between an IDE and an AI service can be useful for:

- AI security research
- Data privacy analysis
- Prompt monitoring
- Sensitive-data detection
- AI application testing
- Debugging AI integrations

This project creates a local traffic-interception layer between the Windsurf VS Code extension and its backend infrastructure.

The interceptor analyzes the traffic and attempts to identify actual AI conversations while filtering unrelated telemetry and background requests.

Sensitive information is masked before relevant data is written to the clean output file.

---

## ✨ Key Features

- 🔍 Intercepts Windsurf/Codeium AI traffic
- 💬 Extracts user prompts
- 🤖 Extracts AI-generated responses
- 🔐 Automatically masks sensitive information
- 🧹 Filters unnecessary background traffic
- 📦 Handles JSON and binary/protobuf-style traffic
- 🌊 Reconstructs streamed AI responses
- 🗂️ Generates structured JSON logs
- 🧪 Useful for AI security and privacy research
- ⚡ Supports mitmproxy local process interception

---

## 🏗️ Architecture

```text
             User
               │
               ▼
      ┌─────────────────┐
      │ Visual Studio   │
      │      Code       │
      └────────┬────────┘
               │
               ▼
      ┌─────────────────┐
      │ Windsurf /      │
      │ Codeium AI      │
      │ Extension       │
      └────────┬────────┘
               │
          HTTPS Traffic
               │
               ▼
      ┌─────────────────┐
      │    mitmproxy    │
      │                 │
      │ windsurf_       │
      │ capture.py      │
      └────────┬────────┘
               │
        Traffic Analysis
               │
        ┌──────┴───────┐
        │              │
        ▼              ▼
 Prompt/Response    Background
   Extraction        Filtering
        │
        ▼
 Sensitive Data
    Masking
        │
        ▼
 ┌──────────────────────┐
 │      JSON Output     │
 ├──────────────────────┤
 │ windsurf_prompts.json│
 │ windsurf_log.json    │
 └──────────────────────┘
```

---

## 🔐 Sensitive Data Masking

One of the main security features of this project is automatic sensitive-data masking.

The interceptor detects patterns that may represent sensitive information and replaces them with safe placeholders.

### Supported Masking

| Sensitive Data | Masked Value |
|---|---|
| OpenAI API Keys | `***OPENAI_KEY***` |
| Anthropic API Keys | `***ANTHROPIC_KEY***` |
| GitHub Tokens | `***GITHUB_TOKEN***` |
| GitHub PATs | `***GITHUB_PAT***` |
| Google API Keys | `***GOOGLE_KEY***` |
| AWS Access Keys | `***AWS_KEY***` |
| AWS Secrets | `***AWS_SECRET***` |
| Bearer Tokens | `***TOKEN***` |
| JWT Tokens | `***JWT***` |
| Passwords | `***PASSWORD***` |
| Email Addresses | `***EMAIL***` |
| Phone Numbers | `***PHONE***` |
| Credit Card Patterns | `***CARD***` |
| Private Keys | `***PRIVATE_KEY***` |
| Generic API Keys | `***API_KEY***` |
| Windows Usernames | `***USER***` |
| Machine IDs | `***MACHINE_ID***` |

This helps reduce the risk of accidentally storing credentials or personal information in generated logs.

---

## 🛠️ Technologies Used

- **Python**
- **mitmproxy / mitmdump**
- **Visual Studio Code**
- **Windsurf / Codeium**
- **Regular Expressions (Regex)**
- **JSON**
- **asyncio**
- **HTTPS traffic inspection**
- **Brotli / Gzip / Deflate decoding**

---

## 📂 Project Structure

```text
Windsurf-AI-Traffic-Interceptor/
│
├── windsurf_capture.py
│
├── windsurf_prompts.json
│
├── windsurf_log.json
│
├── README.md
├── requirements.txt
└── .gitignore
```

### `windsurf_capture.py`

Main Python interception and processing script.

It handles:

- Traffic interception
- Request/response decoding
- Prompt extraction
- AI response extraction
- Stream reconstruction
- Sensitive-data masking
- Background request filtering
- JSON logging

### `windsurf_prompts.json`

Clean output containing extracted prompt/response information.

### `windsurf_log.json`

Full interception/debug log containing intercepted request information.

> ⚠️ Consider excluding raw logs from public repositories if they may contain private or environment-specific information.

---

## ⚙️ Prerequisites

Before running the project, install:

- Python 3.x
- Visual Studio Code
- Windsurf/Codeium extension
- mitmproxy

Install mitmproxy:

```bash
pip install mitmproxy
```

If Brotli-compressed responses need to be decoded:

```bash
pip install brotli
```

---

## 🚀 Running the Interceptor

### Recommended: Local Process Redirect Mode

The script supports mitmproxy's local process interception mode.

```bash
mitmdump -s windsurf_capture.py --mode local:language_server_windows_x64
```

This mode targets the Windsurf language-server process directly.

It can be useful when an application does not respect normal `HTTP_PROXY` environment settings.

### Legacy Proxy Mode

The script can also be started using:

```bash
py windsurf_capture.py
```

The legacy method depends on the application correctly using the configured proxy.

---

## 📊 Output

The project generates two main JSON files.

### Clean Output

```text
windsurf_prompts.json
```

Contains extracted AI interactions.

Example:

```json
{
    "entry_id": 1,
    "timestamp": "2026-07-01T05:56:01+00:00",
    "url": "https://server.codeium.com/...",
    "prompt": "How can I determine whether ***EMAIL*** is spam?",
    "response": "Masked personal details for security reasons."
}
```

### Full Debug Log

```text
windsurf_log.json
```

Contains broader intercepted request/response information useful during debugging.

---

## 🔄 Processing Workflow

```text
Intercept Request
       │
       ▼
Identify Relevant Traffic
       │
       ▼
Decode HTTP Body
       │
       ├── JSON
       ├── Gzip
       ├── Deflate
       ├── Brotli
       └── Binary / Protobuf
       │
       ▼
Extract Conversation Data
       │
       ├── User Prompt
       └── AI Response
       │
       ▼
Reconstruct Streamed Content
       │
       ▼
Mask Sensitive Information
       │
       ▼
Filter Background Noise
       │
       ▼
Write Structured JSON
```

---

## 🧹 Traffic Filtering

AI extensions generate significant background traffic in addition to actual conversations.

The interceptor filters several types of unrelated requests such as:

```text
/api/client/features
/api/client/metrics
RecordAnalyticsEvent
ProductAnalytics
GetFeatureFlags
/health
/ping
```

This helps keep the generated output focused on relevant AI interactions.

---

## 🌊 Streamed Response Handling

AI responses are not always returned as one complete text block.

Some endpoints return responses as multiple small fragments.

The interceptor attempts to:

1. Identify valid text fragments
2. Remove binary/protobuf noise
3. Reassemble fragments
4. Remove duplicated content
5. Reconstruct readable AI responses

This improves the quality of captured conversational data.

---

## 🧪 Example

A user might send:

```text
Using this email address user@example.com,
how can I determine whether it is phishing?
```

Instead of storing the real email address, the logger can store:

```text
Using this email address ***EMAIL***,
how can I determine whether it is phishing?
```

This demonstrates the project's privacy-focused logging approach.

---

## 🔒 Security Considerations

HTTPS interception should only be performed on systems and applications you own or are explicitly authorized to test.

Important considerations:

- Never intercept another person's traffic without authorization.
- Never publish real credentials or authentication tokens.
- Review raw logs before committing them to GitHub.
- Use the project only in controlled development environments.
- Remove test certificates when they are no longer required.
- Avoid using interception configurations on production systems.
- Do not commit virtual environments or temporary traffic data.

---

## 📋 `.gitignore`

A recommended `.gitignore`:

```gitignore
# Python
__pycache__/
*.pyc
*.pyo

# Virtual environment
venv/
.venv/

# Environment variables
.env

# IDE
.vscode/

# OS
.DS_Store
Thumbs.db

# Sensitive/raw traffic captures
windsurf_log.json

# Optional local logs
*.log
```

You can keep a **sanitized example** of `windsurf_prompts.json` in GitHub to demonstrate the output.

---

## 📦 requirements.txt

```txt
mitmproxy
brotli
```

---

## 🎓 Learning Outcomes

Through this project, I explored:

- HTTPS traffic interception
- AI application traffic analysis
- mitmproxy
- AI prompt/response monitoring
- Sensitive-data detection
- PII masking
- Regex-based security filtering
- JSON logging
- Binary/protobuf traffic handling
- Streamed AI response reconstruction
- AI privacy and security concepts

---

## 🔮 Future Enhancements

Potential improvements include:

- Web-based monitoring dashboard
- Real-time traffic visualization
- Configurable masking rules
- Additional AI assistant support
- Risk classification for captured prompts
- Prompt-injection detection
- Automated security reports
- Statistics and analytics dashboard
- Export to CSV
- OWASP LLM security mapping

---

## ⚠️ Disclaimer

This project is intended solely for **educational, research, debugging, and authorized security testing**.

Only intercept traffic from applications and systems that you own or have explicit permission to test.

The author is not responsible for unauthorized or improper use of this project.

---

## 👩‍💻 Author

**Janani M**

B.Tech Information Technology  
Aspiring Cybersecurity Engineer

### Areas of Interest

- 🔐 Cybersecurity
- 🤖 AI Security
- 🛡️ Application Security
- 🔍 Security Testing
- 🐍 Python
- 🔒 Data Privacy
