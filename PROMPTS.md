# TrustVault — AI Prompt Log

This file records AI-assisted development work for TrustVault. Prompt descriptions are summarized for documentation. AI assistance was used to support development and review; implementation details and test results should be verified against the source code and Git history.

## Entry 1 — Project Requirements and Security Design

**Date:** Verify from the original conversation or Git history.

**Area:** Authentication, authorization, and audit logging.

**Prompt summary:** Help plan a secure document-sharing application with administrator, owner, and viewer roles, per-document permissions, and an audit trail.

**AI assistance:** Helped organize project requirements, identify security controls, and plan relevant test cases.

**Validation and outcome:** The project includes role-based access control, document permissions, audit logging, and automated tests. A test run reported 15 passed.

**Specific mistake and fix:** No specific AI mistake and corresponding fix have been confirmed for this entry. Add one only if supported by the actual development history.

**Related commit:** `47ae5a5` — Final submission package with docs and tests. Verify that this commit exists and accurately describes the work.

**Limitations:** Passing tests do not prove that the application is completely secure.

## Entry 2 — Document Access Control and Audit Logging

**Date:** 2026-10-23

**Area:** Authorization, document permissions, and audit integrity.

**Prompt summary:** Assistance with reviewing document-level authorization, permission grants and revocations, protected document operations, and audit logging.

**AI assistance:** Helped review authorization checks for document downloads, metadata updates, deletion, permission management, and administrator-only audit-log access.

**Validation and outcome:** Commit `74eeb3f` is documented as fixing security issues, and commit `c601eff` added security and functionality tests. The reported tests cover audit integrity, denied access, edit permissions, and immediate permission revocation. A test run reported 15 passed.

**Specific mistake and fix:** Review the Git diff and original conversation to record an actual authorization mistake, the correction made, and the test that verified the fix. Do not invent a specific mistake if it cannot be confirmed.

**Related commits:**
- `74eeb3f` — Fix security issues and pass tests.
- `c601eff` — Add TrustVault security and functionality tests.

**Limitations:** Automated tests cannot prove that every endpoint and authorization failure path is secure.

## Entry 3 — Frontend Login and Upload Integration

**Date:** 2026-10-23

**Area:** Frontend integration and API requests.

**Prompt summary:** Assistance with debugging login and document-upload requests between the frontend and FastAPI backend.

**AI assistance:** Helped investigate frontend requests and their interaction with backend endpoints.

**Specific mistake and fix:** Review commit `385b18f` and the corresponding code changes to identify the actual request or integration mistake and document how it was corrected. Do not claim a particular root cause without checking the diff.

**Validation and outcome:** Commit `385b18f` is described in the Git history as fixing login and upload frontend requests. Confirm the behavior with the application and relevant tests.

**Related commit:** `385b18f` — Fix login and upload frontend requests.

**Limitations:** Successful login or upload does not by itself demonstrate that all authorization and file-validation paths are secure.

## Entry 4 — Root Route and Deployment Dependency

**Date:** 2026-10-24

**Area:** Deployment and application startup.

**Prompt summary:** Assistance with diagnosing deployment issues affecting the TrustVault homepage and its runtime dependencies.

**AI assistance:** Helped investigate the root route and the dependency configuration needed for deployment.

**Specific mistake and fix:** Review commits `b06b889` and `e8e5ba9` to record the actual dependency or routing issue, how it was fixed, and how the result was verified.

**Validation and outcome:** The Git history describes `b06b889` as adding the PyJWT deployment dependency and `e8e5ba9` as serving the TrustVault login page from the root route. Verify the live deployment before claiming the issue is fully resolved.

**Related commits:**
- `b06b889` — Add PyJWT dependency for deployment.
- `e8e5ba9` — Serve TrustVault login page from root.

**Limitations:** A successful local run does not guarantee that a cloud deployment has correct environment variables, persistent storage, or production security settings.

## Entry 5 — Document Search and Date Filtering

**Date:** 2026-10-24

**Area:** Document search and frontend usability.

**Prompt summary:** Assistance with adding an upload-date filter alongside the existing document search.

**AI assistance:** Helped review text filtering, date filtering, result counts, empty-result messages, and clearing search fields on logout.

**Specific mistake and fix:** During the review, a duplicate declaration of `selectedDate` was identified in the proposed frontend function. The fix was to keep a single declaration and use it for both filtering and result messages. The empty-result message was also updated to account for date-only searches.

**Validation and outcome:** The user saved the frontend changes and pushed them to GitHub. The push output confirmed that commit `64f2323` was uploaded. Confirm the final code and test the text filter, date filter, no-results state, and logout behavior before treating the feature as fully verified.

**Related commit:** `64f2323` — Verify the actual commit message in Git history before submission.

**Limitations:** Frontend filtering is not a replacement for server-side authorization. Search results must never expose documents that the current user is not allowed to access.

## General Validation Notes

- Commit hashes and descriptions must match the actual Git history.
- Record only AI mistakes and fixes that can be supported by the conversation or code changes.
- Test security-sensitive changes after implementation.
- A successful test run is evidence of tested behavior, not proof of complete security.
- Do not include real passwords, secret keys, access tokens, or private database contents in this file.