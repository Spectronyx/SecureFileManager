c# Secure File Management System

A secure and user-friendly file management system designed to provide robust file handling with advanced security features.

## Features

- **Secure User Authentication**
  - Registration with strong password requirements
  - Login with session management
  - Two-Factor Authentication using PyOTP

- **File Management**
  - Secure file uploads with malware detection
  - AES-256 encryption for all stored files
  - File sharing with granular permissions
  - Comprehensive access logging

- **Security Measures**
  - Input sanitization
  - CSRF protection
  - XSS prevention
  - Malware scanning
  - Encrypted file storage

## Technology Stack

- Python 3 with Flask web framework
- PostgreSQL database with SQLAlchemy ORM
- AES-256 encryption via PyCryptodome
- Bootstrap 5 for responsive UI
- PyOTP for Two-Factor Authentication

## Installation

1. Clone the repository
```bash
git clone https://github.com/rajneesh5566/SecureFileManager
cd secure-file-management
```

2. Install required packages
```bash
pip install -r requirements.txt
```

3. Create a `.env` file with the following variables:
```
DATABASE_URL=postgresql://username:password@hostname:port/database_name
SESSION_SECRET=your_secret_key
```

4. Initialize the database
```bash
python app.py
```

5. Run the application
```bash
python main.py
```

## Usage

1. Register a new account
2. Log in with your credentials
3. Enable Two-Factor Authentication for extra security
4. Upload and manage files
5. Share files with other users

## Project Structure

- `app.py` - Application initialization and configuration
- `main.py` - Entry point for the application
- `auth.py` - Authentication routes and functions
- `file_manager.py` - File handling routes and functions
- `security.py` - Security-related utilities (encryption, sanitization)
- `malware_detection.py` - File scanning for malicious content
- `models.py` - Database models
- `forms.py` - Form definitions and validation
- `templates/` - Jinja2 HTML templates
- `static/` - CSS, JavaScript, and other static assets

## License

MIT
