Project Overview

This project is an AI-driven security platform designed to make AI applications safer, more reliable, and easier to monitor.
The main idea of the project is to create a security gateway for AI applications.
The system combines AI, Retrieval-Augmented Generation (RAG), cybersecurity controls, and monitoring to detect and prevent potentially harmful or unauthorized operations. It protects both user inputs and retrieved information by applying security checks before information reaches the AI model and monitoring the system for suspicious activity.
The platform provides an API backend and a lightweight web interface, allowing users to interact with the system while security mechanisms work in the background.

What Problem Does It Solve?

Modern AI applications, especially applications using LLMs and RAG, can introduce several security risks.

For example:

Malicious or manipulated prompts can influence the AI model.
Sensitive information can accidentally be exposed.
Retrieved documents may contain unsafe or malicious content.
Unauthorized users may access protected resources.
Suspicious activities may go unnoticed without proper monitoring.
Vulnerability information needs to be continuously considered when evaluating threats.

This project addresses these problems by placing a security layer around the AI and RAG pipeline.
Instead of allowing every request to directly reach the AI system, the application first evaluates the request, applies security policies, and monitors the activity.

Technologies Used
Backend
Python — Main programming language
FastAPI — REST API and backend framework
Uvicorn — ASGI server used to run the backend
Python modules — Used to separate security, monitoring, database, and RAG components

AI & RAG
Retrieval-Augmented Generation (RAG) — Provides the AI system with relevant external context
Embeddings — Converts documents and information into vector representations for semantic retrieval
RAG Pipeline — Handles retrieval and integration of relevant information into the AI workflow
Cybersecurity

The security layer includes:

Authentication — Controls user access
RBAC (Role-Based Access Control) — Restricts actions based on user roles
DLP (Data Loss Prevention) — Helps detect and prevent sensitive information from being exposed
Prompt Guard — Detects potentially unsafe or malicious prompts
RAG Guard — Protects the retrieval pipeline from unsafe content or retrieval-related attacks
Threat Engine — Evaluates potential security threats
CVE Data — Vulnerability information can be loaded and used as part of threat analysis

Monitoring
Security event detection
Activity logging
Suspicious behavior monitoring
Threat-related logging

Web
Python-based lightweight web frontend
HTML templates
Static assets
API communication with the backend

How the System Works

1. User Request
The user sends a request through the web interface or API.
The request is first received by the API Gateway.

2. Authentication & Authorization
The system verifies the user's identity and determines what the user is allowed to access.
RBAC can be used to restrict functionality according to user roles.

3. Prompt Security
Before the request reaches the AI/RAG pipeline, the Prompt Guard analyzes the input.
It can help identify potentially malicious or unsafe instructions.

4. Sensitive Data Detection
The DLP module checks whether the request or information being processed contains sensitive data that should not be exposed or transmitted.

5. RAG Security
If the request requires external knowledge, the RAG pipeline retrieves relevant information.
The RAG Guard provides an additional security layer around this process to reduce the risk of unsafe or manipulated retrieved content.

6. Threat Analysis
The Threat Engine evaluates security-related information and can use vulnerability data, including CVE information, as part of the threat-analysis process.

7. AI / RAG Processing
After passing the required security checks, the request continues through the RAG pipeline.
The embedding and retrieval components help find relevant information to provide context for the AI system.

8. Monitoring & Logging
The monitoring layer records relevant security events and detects suspicious activity.
This provides visibility into what is happening inside the application.

9. Response
The processed result is returned to the user through the API and web interface.
