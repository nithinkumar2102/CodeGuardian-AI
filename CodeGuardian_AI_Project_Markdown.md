# CodeGuardian AI

## An Intelligent AI-Powered Code Review and Vulnerability Detection System

**Student:** Shankara Nithin Kumar\
**Mentor:** Akshara\
**Domain:** Artificial Intelligence & Machine Learning\
**GitHub Repository:**
https://github.com/nithinkumar2102/CodeGuardian-AI

------------------------------------------------------------------------

## 1. Executive Summary

CodeGuardian AI is a Python-based application that helps developers
review Python source code for potential security weaknesses. It combines
Bandit static analysis, a Streamlit interface, and a locally hosted
Llama 3 model accessed through Ollama. Users can paste Python code or
upload a `.py` file, run a scan, inspect findings, and request
AI-generated explanations and safer coding suggestions.

The application also supports rescanning suggested code, viewing scan
history, and downloading scan information in JSON format. It is an
educational code-review aid, not a replacement for professional security
testing.

## 2. Introduction

Developers may introduce vulnerabilities through risky function usage,
unsafe input handling, exposed credentials, or insecure data processing.
Manual review can take time. Static analysis can identify certain risky
patterns without executing the submitted program.

CodeGuardian AI provides an accessible interface for Python static
analysis, with optional AI assistance to explain findings and suggest
possible improvements.

### Problem Statement

Learners and developers need a simple way to inspect Python code for
potential security issues and understand why findings matter. This
project combines automated static scanning with readable explanations
and suggested alternatives.

### Scope and Limitations

-   Supports Python source code pasted into the application or uploaded
    as a `.py` file.
-   Bandit detects only patterns covered by its rules; it cannot find
    every vulnerability.
-   AI explanations and suggested fixes may be inaccurate and must be
    reviewed.
-   The displayed score is illustrative, not a formal security rating.
-   The Bandit scanning workflow analyses source code; it does not
    execute the submitted program.

## 3. Project Objectives

-   Build a Streamlit interface for Python code input and file upload.
-   Integrate Bandit for static security analysis.
-   Display findings with available severity, confidence, test ID, and
    line information.
-   Use Ollama with Llama 3 for AI-assisted explanations and suggested
    improvements.
-   Allow code comparison, rescanning, scan history, and JSON report
    downloads.

## 4. Methodology and Results

### Technologies Used

  Technology   Purpose
  ------------ --------------------------------------------
  Python       Application logic
  Streamlit    Interactive user interface
  Bandit       Python static security analysis
  Ollama       Local language-model runtime
  Llama 3      AI explanations and suggested improvements
  JSON         Scan history and report data

### Application Workflow

1.  The user enters Python code or uploads a `.py` file.
2.  The application prepares a temporary source file.
3.  Bandit runs as a subprocess and returns JSON findings.
4.  Streamlit displays findings and an illustrative score based on
    severity counts.
5.  When Ollama is available, Llama 3 can explain findings and suggest
    safer code.
6.  The user reviews suggestions, compares code, and can rescan it.
7.  Scan records can be stored locally and downloaded in JSON format.

### Architecture

**Static analysis flow:**\
User → Streamlit interface → temporary Python source file → Bandit
scanner → JSON findings → results dashboard.

**AI assistance flow:**\
Relevant code and findings → local Ollama API → Llama 3 → explanation or
suggested code displayed in Streamlit.

### Results

The application includes code input and upload, Bandit scanning, a
findings view, an illustrative score, AI review and fix-suggestion
controls, code comparison and rescanning, scan history, and JSON
download options.

In a demonstrated test, Bandit identified risky use of `os.system`.
Actual results depend on the submitted code and the scanner rules that
apply.

### Screenshots

Add actual screenshots of the working application below. Include only
features that were successfully tested.

1.  Application home page and code input.
2.  Bandit scan results.
3.  AI explanation.
4.  Suggested code and comparison.
5.  Scan history or report download.

## 5. Social / Industry Relevance

Secure software development helps reduce risks to systems and data. This
project makes selected static-analysis findings easier to view and
understand, supporting secure-coding awareness. It is a learning aid and
should be used with code review, testing, dependency checks, and other
security practices. It is not a full security audit.

## 6. Learning and Reflection

Through this project, I gained practical experience in Python
application development, Streamlit interfaces, invoking command-line
tools from Python, parsing JSON results, and displaying findings. I
learned the strengths and limitations of static analysis and the
importance of reviewing AI-generated suggestions.

Integrating Ollama and Llama 3 helped me understand how a locally hosted
language model can assist with explanations. The project improved my
debugging, problem-solving, documentation, and software integration
skills.

## 7. Future Scope and Conclusion

### Future Scope

-   Add more static-analysis tools and security rules.
-   Introduce configurable scan profiles and improved finding filters.
-   Improve validation and testing of AI-generated suggestions.
-   Add PDF and HTML report export options.
-   Explore additional programming languages through suitable analyzers.
-   Add automated tests and evaluate against curated secure and
    intentionally vulnerable examples.

### Conclusion

CodeGuardian AI combines Python static analysis with AI-assisted
explanations in a Streamlit application. Bandit identifies supported
security patterns, while Ollama with Llama 3 can explain findings and
suggest possible improvements. The application also provides code
comparison, rescanning, scan history, and JSON reports.

The prototype provides an accessible way to learn about Python code
security. Scanner coverage is limited, and all suggested changes require
human review and testing.
