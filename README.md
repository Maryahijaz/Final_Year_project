MonitorApp  is an independent security monitoring and analysis system developed as part of the TrustZAI platform. It is designed to collect, process, and monitor security-related application logs while providing AI-powered analysis of potential threats, attacks, suspicious activities, and anomalies. The system combines a FastAPI backend, Flask-based web interface, JWT authentication, role-based access control (RBAC), and a Mistral AI model running through Ollama to provide a secure and centralized monitoring environment.

The application reads structured security logs, including application activity, security events, and blocked requests, and generates real-time statistics such as total requests, blocked requests, success rates, detected attack types, and user activity. Authorized users can access these logs through the monitoring dashboard and investigate security events through dedicated API endpoints.

A key component of MonitorApp is its AI-powered security analyzer. Security logs are processed and provided as context to the Mistral model, which evaluates events, identifies potential threats and suspicious patterns, determines risk levels such as LOW, MEDIUM, HIGH, and CRITICAL, and generates security recommendations. This allows security analysts to investigate large amounts of log data more efficiently and obtain an additional layer of automated analysis.

Security is integrated into the architecture through JWT-based authentication, RBAC permissions, and a dedicated prompt guard. The guard detects potential prompt-injection and privilege-escalation attempts, sanitizes user input, and prevents unauthorized users from attempting to bypass security controls. Administrators and analysts are assigned different permissions according to their roles, ensuring that access to monitoring and analysis capabilities follows the principle of least privilege.

The overall architecture separates the monitoring system from the main TrustZAI application, allowing security events to be analyzed through an independent interface and security layer. This separation provides a dedicated environment for **security monitoring, log analysis, threat detection, AI-assisted investigation, and incident awareness**.

### Key Technologies

* FastAPI & Uvicorn — Backend API and service layer
* Flask — Web monitoring interface
* Mistral + Ollama — AI-powered security log analysis
* JWT & bcrypt — Authentication and credential protection
* RBAC — Role-based authorization and permission management
* Prompt Guard — Prompt-injection and privilege-escalation detection
* JSON Logs — Structured security event storage and analysis
* HTML/CSS/JavaScript — Monitoring dashboard and frontend interface
