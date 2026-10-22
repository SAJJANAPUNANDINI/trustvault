# TrustVault - Secure Document Management System

TrustVault is a secure, server-enforced document sharing and management platform built with **FastAPI**, **SQLite**, and **JWT Authentication**. It meets strict non-negotiable security requirements including server-side authorization, immutable audit logging, and real-time permission revocation.

## Features
- **Server-Side Authorization**: Every request is independently authorized by the server; frontend UI controls are never trusted.
- **Granular Permissions**: Secure document sharing with immediate revocation capabilities.
- **Comprehensive Audit Logs**: Tracks all user actions, logins, and blocked unauthorized access attempts.
- **File Validation**: Strict extension filtering preventing malicious uploads.

## Setup & Installation

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd trustvault