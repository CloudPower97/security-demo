# Security Demo Node.js Application

This repository contains a simple Node.js application built with Express, intentionally designed with simulated security vulnerabilities for educational purposes. The goal is to use various security tools to identify and fix these vulnerabilities.

## Prerequisites

- Docker Desktop (or Docker Engine)
- Node.js and npm
- Git
- VS Code (recommended IDE)
- CLI tools: Trivy, Snyk, Checkov, Vault (for the Vault example)

## Repository Structure

```bash
security-demo-node/
├── Dockerfile
├── server.js
├── package.json
├── package-lock.json
├── views/
│   └── index.html
├── .checkov.yml
├── vault_example.js
└── README.md
```

## Simulated Vulnerabilities

This application includes the following simulated vulnerabilities:

1. **Vulnerable Dependencies:** The `package.json` file includes dependencies with known security vulnerabilities.
2. **Command Injection:** The `/command` endpoint in `server.js` is vulnerable to command injection.
3. **Cross-Site Scripting (XSS):** The `/xss` endpoint in `server.js` is vulnerable to reflected XSS.
4. **SQL Injection (Simulated):** The `/users` endpoint in `server.js` simulates a SQL injection vulnerability.
5. **Insecure Direct Object Reference (IDOR):** The `/data` endpoint in `server.js` is vulnerable to IDOR.
6. **Server-Side Request Forgery (SSRF):** The `/fetch` endpoint in `server.js` is vulnerable to SSRF.
7. **Insecure Dockerfile Configuration:** The `Dockerfile` includes insecure practices like running as the root user.
8. **Hardcoded Secret:** A sensitive API key is hardcoded in `server.js`.
9. **Weak Express Configuration:** The Express application may lack proper security headers or error handling.
10. **Verbose Error Messages:** The application is configured to show detailed error messages.
11. **Missing Rate Limiting:** The application lacks rate limiting on endpoints.

## Getting Started

1. **Clone the repository:**

   ```bash
   git clone <repository_url>
   cd security-demo-node
   ```

2. **Install Node.js dependencies:**

   ```bash
   npm install
   ```

3. **Build the Docker image:**

   ```bash
   docker build -t security-demo-node .
   ```

4. **Run the Docker container:**

   ```bash
   docker compose up -d
   ```

   The application should now be running at `http://localhost:3000`.

## Using Security Tools

Use the following tools to identify vulnerabilities:

- **Trivy:** Scan the Docker image for vulnerabilities.

  ```bash
  trivy image --security-checks secret,vuln security-demo-node-app > trivy-results.txt
  ```

- **Snyk:** Scan the project for vulnerable dependencies and code issues.

  ```bash
  snyk test
  ```

  ```bash
  snyk code test
  ```

- **Checkov:** Scan infrastructure as code (Dockerfile) and configuration files for misconfigurations.

  ```bash
  checkov -d .
  ```

## Exercise

1. Use the security tools to identify all simulated vulnerabilities.
2. Analyze the output of each tool and understand the reported vulnerabilities.
3. Create a new Git branch (`git checkout -b fix/security`).
4. Fix each identified vulnerability in the code and configuration files.
5. Re-run the security tools to verify that the vulnerabilities have been fixed.
6. (Optional) Implement secure secrets management using Vault.
7. Commit your changes and explore the differences between the vulnerable and fixed versions.

This exercise provides hands-on experience with identifying and remediating a range of common web application vulnerabilities using industry-standard security tools.
