# Secure File Management System

This document outlines the architecture, functionality, and security measures of the Secure File Management System, which has been migrated from Flask to Django.

## Overview

The Secure File Management System is a web application designed to allow users to securely upload, store, and share files. It places a strong emphasis on security by incorporating AES-256 encryption at rest, malware scanning upon upload, and mandatory Two-Factor Authentication (2FA) for all users. 

## Key Features

1. **User Authentication & Authorization**
   - Secure registration and login flow using Django's built-in authentication system.
   - Mandatory Two-Factor Authentication (2FA) via time-based one-time passwords (TOTP). Users must set up an authenticator app (like Google Authenticator or Authy) to access the system.
   - Role-based access control (Admin vs. Regular User).

2. **Secure File Upload & Storage**
   - AES-256 encryption of all uploaded files using `cryptography.hazmat` primitives before they are written to disk.
   - Files are stored on disk purely in their encrypted state, ensuring data securely resides at rest.
   - Support for common file types (PDF, Word, Excel, images, etc.) with a size limit of 16MB.

3. **Malware Scanning**
   - Basic signature matching for common malware signatures (EICAR, etc.).
   - Heuristics/Pattern matching for potentially malicious patterns within specific file types.
   - Protection against suspicious file types disguised under safe extensions (e.g., an executable disguised as a `.jpg`).

4. **File Sharing**
   - Users can securely share access to their uploaded files with other registered users in the system.
   - Permissions can be set as 'Read Only' or 'Read & Edit', providing granular access control.
   - File owners maintain full control to revoke access at any time.

5. **Audit Logs**
   - Access history to files is tracked explicitly (uploads, downloads, views, and sharing events) along with IP addresses to ensure visibility into file activity.

6. **Admin Dashboard**
   - Dedicated dashboard for administrators providing a holistic view of the system.
   - Ability to review all users, inspect all configured files, identify malicious uploads, and monitor audit logs across the application.

## System Architecture

The project has been structured as a standard Django application composed of two primary apps:

- **`accounts` App**: 
  - Handles the custom CustomUser model.
  - Controls authentication flows, session handling, 2FA setup, and verification.

- **`files` App**:
  - Manages File metadata, FileShare permissions, and AccessLogs relationships.
  - Implements the AES encryption/decryption logic.
  - Includes malware scanning rules and definitions.
  - Serves file downloads in chunks via a secure generator pattern to avoid saving decrypted temporary files on disk.

## Security Controls

- **CSRF Protection**: Native Django Cross-Site Request Forgery protection on all forms.
- **SQL Injection Prevention**: Exclusive usage of Django's Object-Relational Mapper (ORM), automatically parameterizing queries.
- **XSS Protection**: Jinja to Django template migration continues to escape context variables safely by default.
- **In-Memory Decryption**: Files requested for download are decrypted on-the-fly and streamed directly to the user to prevent accidental leakage of unencrypted data residing on the server filesystem.
- **Secret Key Handling**: Django's SECRET_KEY and the custom ENCRYPTION_KEY are loaded via environment properties ensuring they do not leak into source control.

## Running Locally

To run the application locally:
1. Install dependencies: `pip install -r requirements.txt`
2. Apply database migrations: `python manage.py migrate`
3. Run the Django development server: `python manage.py runserver`
4. Access the server at `http://127.0.0.1:8000/`
