# AI Prompt Engineering & Correction Log (`PROMPTS.md`)

This log tracks interactions with AI coding assistants during the development of TrustVault, highlighting where the AI's suggestions fell short—particularly regarding security boundaries—and how those flaws were manually corrected.

---

## Entry 1: Authorization & Permission Caching (Date: October 20, 2026)
- **What was asked:** "Write a FastAPI dependency for document downloading that checks if a user has access by storing permissions inside the JWT token claims to speed up requests."
- **What it produced:** The AI generated a JWT creation function that encoded a list of `permitted_document_ids` directly into the token payload, and a download endpoint that checked those claims without hitting the database.
- **What was wrong with it:** This introduced a critical security flaw: **stale permissions**. If an owner revoked a user's access, the user could still download the file until their JWT token expired, because the revocation was never checked against a live database state. This violates the core rule of immediate permission revocation.
- **What was done instead:** Rejected the JWT claim caching approach. Implemented real-time, dynamic database lookups on every request against the `permissions` table so revocation takes effect instantly.
- **Fix reference:** Enforced real-time database permission lookup on download requests.

---

## Entry 2: Audit Trail & Failure Logging (Date: October 21, 2026)
- **What was asked:** "How should I implement audit logging for successful downloads and uploads in FastAPI?"
- **What it produced:** The AI provided an asynchronous background task decorator that logged successful API requests to a JSON file. It completely omitted logging failed or unauthorized access attempts.
- **What was wrong with it:** 
  1. JSON files lack ACID compliance and concurrency safety under multi-process loads.
  2. Ignoring *unauthorized* access attempts defeats the purpose of an audit trail in a secure vault, since security teams need visibility into who is trying to breach restricted files.
- **What was done instead:** Replaced JSON logging with an immutable, append-only SQLite `audit_logs` table managed via robust context managers, explicitly capturing both successful operations and `UNAUTHORIZED_ACCESS` events with user IDs and timestamps.
- **Fix reference:** Added append-only audit trail logging for unauthorized and authorized actions.

---

## Entry 3: SQLite Concurrency & Test Locking (Date: October 22, 2026)
- **What was asked:** "Fix this pytest error: `sqlite3.OperationalError: database is locked` happening when running multiple test requests concurrently."
- **What it produced:** The AI suggested disabling SQLite journaling entirely using `PRAGMA journal_mode=OFF;` or adding `time.sleep(1)` inside test loops.
- **What was wrong with it:** Disabling journal mode risks database corruption during unexpected crashes, and artificial sleep timers make test suites unnecessarily slow and brittle.
- **What was done instead:** Configured proper connection timeouts (`timeout=30.0`) and enforced Python `with sqlite3.connect(...) as conn:` context managers across all endpoints to guarantee immediate connection closure and lock release.
- **Fix reference:** Added connection timeout and context managers to resolve SQLite locking.

---

## Entry 4: File Upload Validation (Date: October 22, 2026)
- **What was asked:** "Give me a quick file upload handler in FastAPI."
- **What it produced:** A simple handler that saved `file.file` directly to disk using `file.filename` without inspecting or sanitizing the extension.
- **What was wrong with it:** Allowing raw, unvalidated filenames opens the server up to path traversal attacks (`../../filename`) and arbitrary file uploads (e.g., uploading executable `.exe` or `.php` scripts into the upload directory).
- **What was done instead:** Implemented a strict server-side whitelist (`ALLOWED_EXTENSIONS = {".pdf", ".docx", ".txt", ".png", ".jpg", ".jpeg"}`) using `os.path.splitext` and rejected unauthorized types with a `400 Bad Request`.
- **Fix reference:** Implemented strict file extension whitelist validation on upload.

---

## Entry 5: AI Document Sharing Recommendations (Date: October 22, 2026)
- **What was asked:** "Design an AI feature that suggests who should have access to a newly uploaded document based on category."
- **What it produced:** Code that automatically inserted permission rows into the database if the AI confidence score for a user match was above 85%.
- **What was wrong with it:** **Violation of core safety bounds.** The AI attempted to *widen access on its own* without human confirmation. The challenge rules explicitly state: *"The machine must never widen access on its own. A person confirms, and both the suggestion and the decision go into the audit."*
- **What was done instead:** Restricted the AI capability strictly to a *suggestion endpoint* returning candidate users. Requiring explicit owner confirmation via an explicit `/grant` button, and logging both the suggestion and final human approval to the audit trail.
- **Fix reference:** Ensured AI permission suggestions require explicit human confirmation and auditing.