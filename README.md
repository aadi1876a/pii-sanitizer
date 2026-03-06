# 🛡️ PII Sanitizer

Automated Personal Identifiable Information Detection & Sanitization Platform.

## Live URL
https://pii-sanitizer.onrender.com/ui

## Login Credentials
| Role  | Username | Password | Admin Key |
|-------|----------|----------|-----------|
| Admin | admin    | admin123 | ADMINKEY  |
| User  | user     | 1234     | —         |

## Supported File Types
PDF, DOCX, TXT, CSV, JSON, SQL, PNG, JPG, JPEG

## Run Locally
```bash
cd backend
pip install -r requirements.txt
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```
Open: http://localhost:8000/ui
