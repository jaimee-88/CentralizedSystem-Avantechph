# Avantech Centralized System Documentation

## 1. System Overview

Avantech Centralized System is a Django-based internal portal that combines:
- secure user authentication and access control,
- role and permission management,
- client and quotation management,
- asset inventory tracking,
- asset accountability (borrow, approve/decline, return), and
- in-app notification support.

The system is built as a server-rendered web application using Django templates, with Bootstrap-based UI and targeted JavaScript enhancements for modals, tables, and bulk actions.

---

## 2. Technology Stack

Core stack:
- Django 6.0.4
- SQLite (default local database)
- Django Templates + static CSS/JS

Security and authentication add-ons:
- django-axes (login lockout and brute-force mitigation)
- django-otp (TOTP and OTP workflow)
- django-simple-captcha (captcha on sensitive auth flows)
- argon2-cffi (strong password hashing)

Other libraries:
- python-dotenv (environment variable loading)
- qrcode (asset tagging generation support)
- Pillow (image processing support)

See dependency list in requirements.txt.

---

## 3. Project Structure

Top-level app layout:
- AvantechPortal/manage.py: Django entry point
- AvantechPortal/AvantechPortal/settings.py: global configuration
- AvantechPortal/AvantechPortal/urls.py: root URL routing
- AvantechPortal/core/: main business domain app
- AvantechPortal/templates/: shared and page templates
- AvantechPortal/static/: custom CSS/JS
- AvantechPortal/docs/: internal project documentation
- AvantechPortal/logs/: runtime security logs
- AvantechPortal/db.sqlite3: local database file

Key core module files:
- core/models.py: all domain entities and model logic
- core/views.py: route handlers and page workflows
- core/forms.py: form validation and UI form behavior
- core/urls.py: app route definitions
- core/middleware.py: inactivity session timeout enforcement
- core/backends.py: custom permission backend behavior
- core/auth_utils.py: shared auth/session helpers
- core/notifications.py: notification creation utilities
- core/signals.py: model and auth related signal hooks

---

## 3.1 Local Development (Important)

When you pull new code, switch branches, or deploy to a new environment, always apply migrations before running the server. If you skip this, you may see runtime errors like `OperationalError: no such table ...`.

Recommended dev command (runs `migrate` then starts the server):

- `bash scripts/dev-up.sh`

Manual equivalent:

- `cd AvantechPortal`
- `../.venv/bin/python manage.py migrate`
- `../.venv/bin/python manage.py runserver`

---

## 4. Core Functional Modules

### 4.1 Authentication and Account Security

Primary capabilities:
- login/logout flow with lockout support,
- OTP verification step,
- optional email verification flow,
- secure password change/reset,
- captcha validation for sensitive entry points,
- inactivity-based auto logout.

Important security controls:
- strict password validation (minimum length and common/numeric checks),
- Argon2 password hasher prioritized,
- secure session and CSRF cookie settings (configurable by environment),
- lockout and cooldown policies via django-axes,
- request-level inactivity timeout middleware.

Relevant routes include:
- login, logout, OTP verify,
- email verification send/confirm,
- password change/reset,
- lockout notice and support lockout center.

### 4.2 Users and Roles Management

Users module supports:
- create/update/delete users,
- bulk user actions (status update, role update, delete),
- profile quick view,
- branch assignment in user profile.

Roles module supports:
- create/update/delete Django groups,
- assign grouped permissions via checkbox UI,
- role list and role detail interactions.

Permission behavior:
- direct user permissions can override group permissions when explicit direct permissions exist.
- implemented in core/backends.py through ExplicitUserPermissionBackend.

### 4.3 Clients and Quotations

Client management:
- create, edit, delete, list, and quick view clients,
- track lead lifecycle using statuses,
- capture lead disposition reason and proof image for key statuses,
- support bulk status updates and bulk deletes.

Quotation management:
- create quotations per client with versioning,
- upload one or multiple supporting documents,
- negotiation status tracking,
- quotation document view/download workflows.

### 4.4 Asset Tracker

Asset tracker provides:
- department management,
- item type management (name, code, prefix, active state),
- asset item creation/update/delete,
- parent item and variant model,
- automatic item code generation by prefix,
- image support for parent items and variants,
- optional item note and specification metadata,
- stock visibility and low-stock indicators,
- modal-based row detail view for variants.

Asset tagging:
- generate tag batches,
- view printable tagging document,
- delete single or bulk generated batches.

### 4.5 Asset Accountability (Borrowing)

Accountability workflows include:
- submit borrow requests,
- pending review queue,
- approve or decline requests with reason,
- return handling and proof image uploads,
- list and summary reports with CSV exports,
- bulk decision and bulk records actions.

Stock handling behavior:
- approved borrow request deducts stock,
- returned item restores stock,
- stock is computed across parent + variant inventory group.

### 4.6 Notifications

Notification features:
- in-app notification feed and list,
- mark read operations,
- event-driven messages for important actions (for example request updates).

---

## 5. Data Model Summary

Main entities:
- UserProfile: extends user metadata (status, branch, avatar, verification flags)
- LoginEvent: authentication attempt logging
- EmailVerificationToken: token lifecycle for email verification
- Notification: user-targeted in-app notifications
- Client: lead and customer detail record
- ClientQuotation: per-client quotation versions
- ClientQuotationDocument: multiple files per quotation
- AssetDepartment: asset department ownership
- AssetItemType: configurable item taxonomy + prefix
- AssetItem: core inventory entity (supports parent/variant, note, specification, stock)
- AssetItemImage: multiple image rows linked to asset item
- AssetTagBatch: generated tagging batch metadata
- AssetTagEntry: per-item snapshot row in a batch
- AssetAccountability: borrow/return workflow record
- AssetReturnProof: return proof image uploads

Relationship highlights:
- AssetItem can self-reference via parent_item for variants.
- AssetAccountability links a borrower user and asset item.
- ClientQuotation links to Client with unique (client, version).
- ClientQuotationDocument supports multi-file attachment per quotation.

---

## 6. Permissions and Authorization Model

Authorization uses:
- Django auth permissions,
- roles via Group assignments,
- explicit user permission assignments,
- custom backend precedence rule.

Backend precedence rule:
- if user has at least one explicit direct permission, group permissions are ignored for permission checks,
- otherwise group permissions are used normally,
- superusers retain full access.

This design allows precise exceptions for users without changing role definitions.

For accountability-specific role checklist, see docs/asset_accountability_permissions_checklist.md.

---

## 7. Important Request Flows

### 7.1 Login Flow
1. User submits username/password + captcha.
2. Failed attempts are rate-limited and tracked.
3. django-axes lockout policy can block repeated failures.
4. OTP step validates second factor before final access.

### 7.2 Borrow Request Flow
1. User opens accountability borrow form.
2. Selectable items are limited to in-stock inventory.
3. Submit creates pending request.
4. Reviewer approves or declines.
5. Approval deducts stock; decline leaves stock unchanged.
6. On return, stock is restored and return proof may be uploaded.

### 7.3 Asset Detail Modal Flow
1. User clicks a parent item row in asset list.
2. Modal content is loaded through an async endpoint.
3. Modal displays item details, optional image/note/specification section, and variants table.
4. Variant and parent image viewer opens via popup modal preview.

---

## 8. Configuration and Environment Variables

Required:
- DJANGO_SECRET_KEY

Common runtime variables:
- DJANGO_DEBUG
- DJANGO_ALLOWED_HOSTS
- DJANGO_ALLOW_LAN_HOSTS
- SESSION_COOKIE_SECURE
- CSRF_COOKIE_SECURE
- SESSION_COOKIE_AGE
- SESSION_TIMEOUT_SECONDS
- PASSWORD_RESET_TIMEOUT

Email variables:
- DEFAULT_FROM_EMAIL
- EMAIL_BACKEND
- EMAIL_HOST
- EMAIL_PORT
- EMAIL_HOST_USER
- EMAIL_HOST_PASSWORD
- EMAIL_USE_TLS

Lockout/captcha variables:
- AXES_FAILURE_LIMIT
- AXES_COOLOFF_TIME_HOURS
- CAPTCHA_TIMEOUT
- CAPTCHA_LENGTH

Defaults are defined in settings.py when variables are absent (except DJANGO_SECRET_KEY which is required).

---

## 9. Local Setup Guide

### 9.1 Prerequisites
- Python 3.11+ recommended
- pip

### 9.2 Installation
1. Open terminal at project root (AvantechPortal).
2. Create and activate virtual environment.
3. Install dependencies:
   pip install -r requirements.txt

### 9.3 Environment File
Create .env in AvantechPortal root with at least:
- DJANGO_SECRET_KEY=your-secret
- DJANGO_DEBUG=True
- DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost,portal.avantechph.local
- DJANGO_ALLOW_LAN_HOSTS=True

### 9.4 Database and Admin
1. Run migrations:
   python manage.py migrate
2. Create superuser:
   python manage.py createsuperuser

### 9.5 Run Server
- For standard Django dev server:
  python manage.py runserver
- For access from other devices on the same Wi-Fi:
  python manage.py runserver 0.0.0.0:8000
- Open the site from another device using:
  http://YOUR-COMPUTER-LAN-IP:8000
- If you want the browser URL to stay as portal.avantechph.local without showing :port, serve the app on port 80 through a local reverse proxy or bind the app directly to port 80.

---

## 10. Static, Media, and Logs

Static files:
- static/css/site.css
- static/js/form_enhancements.js

Media files:
- stored under media/ (avatars, client docs, asset images, return proofs)

Logs:
- security and auth events are written to logs/security.log
- logger names include auth_security and axes

---

## 11. Operational Notes

- In development, media files are served only when DEBUG=True.
- Session timeout middleware logs out inactive authenticated users.
- Bulk actions in list pages rely on checkbox selection and confirmation modals.
- Asset stock and accountability behavior are tightly coupled; avoid bypassing model methods for stock-changing operations.

---

## 12. Recommended Maintenance Practices

- Run python manage.py check after template/form/view changes.
- Keep migrations small and focused; remove unrelated auto-generated operations when needed.
- Validate permission matrices whenever roles or custom auth backend behavior changes.
- Back up SQLite data before large schema updates in non-dev environments.
- Keep docs in docs/ updated whenever new modules or workflows are introduced.

---

## 13. Related Internal Documentation

- docs/asset_accountability_permissions_checklist.md: role setup guide for accountability flow.
