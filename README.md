# 🛡️ CodeGuardian AI

### An Intelligent AI-Powered Code Review and Vulnerability Detection System

CodeGuardian AI is an AI-assisted Python security analysis application that identifies potential vulnerabilities using Bandit and provides intelligent code reviews and safer coding suggestions using a locally running Llama 3 model through Ollama.

## Features

* **Python Code Input:** Paste Python source code or upload `.py` files.
* **Static Security Analysis:** Scan Python code using Bandit.
* **Vulnerability Detection:** Display security findings with severity, confidence, test ID, and line number.
* **Security Dashboard:** View an illustrative security score and vulnerability summary.
* **AI Code Review:** Get explanations of security findings using Llama 3.
* **AI Fix Suggestions:** Generate safer alternative code.
* **Code Comparison:** Compare original and suggested code and rescan the suggested version.
* **Scan History:** Save and view previous scan records.
* **Report Generation:** Download security reports and scan history in JSON format.

## Technology Stack

* Python
* Streamlit
* Bandit
* Ollama
* Llama 3
* JSON

## Installation and Setup (Windows)

### 1. Create a virtual environment

```powershell
py -m venv .venv
```

### 2. Activate the environment

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Install and configure Ollama

Install Ollama for Windows, then download the model:

```powershell
ollama pull llama3:latest
```

Make sure the Ollama service is running.

### 5. Start the application

From the project root:

```powershell
cd CodeGuardianAI
python -m streamlit run app.py
```

The application will open in your browser.

## Project Structure

```text
CodeGuardianAI_Starter/
│
├── .venv/
│
├── CodeGuardianAI/
│   ├── app.py
│   ├── app_backup.py
│   ├── README.md
│   └── requirements.txt
│
└── codeguardian_scan_history.json
```

## Security Notice

CodeGuardian AI is an educational security analysis tool. Bandit performs static analysis; submitted Python code is not executed by the scanner. AI-generated suggestions may contain errors and must be reviewed and tested before use.

The application may produce false positives or miss vulnerabilities. Its security score is illustrative and is not a formal security rating. Only analyze code you are authorized to review.
