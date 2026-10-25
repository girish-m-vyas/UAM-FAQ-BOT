## v21 — FAQ routing + complete JML lifecycle fields

- FAQ now routes monthly questions to structured Monthly Requests data before user-count logic or Groq.
- Questions such as `total request closed in June 2026` return the exact loaded monthly figure (for the sample dataset: 326).
- Monthly FAQ support includes Created, Closed, Pending, SLA Breached, Category Breakdown, App Created Requests, App Closed Requests, and App Closure %.
- User-count routing is restricted to explicit user/account/employee questions, preventing unrelated `total` questions from returning User Management counts.
- JML records are normalized into one canonical schema and legacy duplicate columns such as `Emp ID`, `Name`, `Type`, and `Date` are removed.
- User Management lifecycle events now populate Employee ID, Employee Name, Portal Username, Email ID, Event Type, Department, Previous Department, Grade, Designation, Manager, Effective Date, Applications, Access Role, Remarks and Status.
- Portal/JML email addresses are normalized to the `@admin.com` domain.
- Existing JML rows are enriched from User Management where matching employee identities exist.
- Bulk-user manager/joining-date/status handling was corrected.


## v19 — FAQ count consistency & guest FAQ

- FAQ current-user count questions now use the exact User Management KPI snapshot shown in the browser.
- If the Admin directory is not loaded, FAQ rebuilds aggregate counts from saved JML lifecycle records and includes the primary Admin account.
- Logged-out users can use FAQ without receiving `Authentication required`.
- Guest FAQ access is read-only: aggregate user counts and general UAM guidance are available, while detailed employee directory context remains restricted to Admin sessions.
- Current user-count questions are answered deterministically before Groq, preventing the model from confusing JML event counts with live account status.
# RBL UAM Hub - Groq Edition

1. Copy `.env.example` to `.env`.
2. Put your Groq API key in `GROQ_API_KEY`.
3. Run `npm install`.
4. Run `npm start`.
5. Open http://localhost:3000.
6. Verify http://localhost:3000/health shows `aiConfigured: true`.

Default model: `openai/gpt-oss-120b`. Change `GROQ_MODEL` if desired.
Never commit `.env` to GitHub.

## v3 additions
- Bulk portal user creation from CSV attachment. Download the template from User Management. Columns: `name,username,password,role,department`. Maximum 500 rows per upload; validation and duplicate checks are enforced server-side.
- Application Handover Tracker. Add an application and owner, then track each handover step as Not Started, In Progress, or Completed with an overall progress percentage. Tracker state is stored in browser localStorage in this demo build.

## v4 sample data templates
Data Manager now includes downloadable, pre-populated CSV samples for ACM Applications, Joiner/Mover/Leaver records, and Monthly Requests. Sample files are stored under `public/samples/`. A Bulk User Creation sample is also included there for testing.


## v6 user lifecycle
User Management now supports email, employee code, grade, designation and editing. Add creates a Joiner event, department change creates a Mover event, and delete creates a Leaver event in the JML view. The Light theme replaces the old RBL label.

## v8 enhancements
- JML table hides empty/irrelevant columns and never displays password fields.
- Monthly dashboard supports category breakdown, application created requests, application closed requests, and closure percentage.
- CSV files require an explicit Upload action after file selection.
- SOP content is optional when an attachment is provided; otherwise content is required.
- ACM imports append to existing data. Admin/Application Team can edit/delete records and remove duplicate application entries.
- Audit workspace includes visible custom queries and an evidence library. Text/CSV/JSON/Markdown evidence is indexed into FAQ/Audit AI context; binary evidence is searchable by filename/metadata.
- FAQ includes Clear Chat, updated UAM helpdesk (bank.uam@rblbank.com), and escalation matrix (L1 BankUAM, L2 Girish/Manali, L3 Joel B).
- New Application Team role can manage ACM, SOP, and application onboarding/handover. Viewer remains read-only.
- User Management is compacted to show more fields and user cards above the fold.


## v9 changes
- Removed the Joiner/Mover/Leaver preview table from Data Manager.
- Added Audit Team role with Audit Q&A and read-only evidence-library access.
- Audit evidence upload/delete is restricted to Admin/UAM team.
- SOP add controls are available only to Admin and Application Team.
- Data record-count pill is visible only to Admin.
- User Management layout was compacted into a responsive dashboard with denser form and user cards.

## v10 fixes
- JML CSV Upload now commits imported rows directly to the operational Joiner / Mover / Leaver dataset and renders them immediately.
- JML Save also correctly merges pending pasted/uploaded rows instead of saving an empty state.
- SOP attachments now extract readable content from PDF, DOCX, TXT/MD/CSV/JSON and XLS/XLSX in the browser. If SOP Content is blank, extracted attachment text becomes the SOP body.
- Previously saved attachment-only SOPs are re-read when opened, where possible, so their content can be displayed without recreating the SOP.
- Legacy `.doc` should be converted to `.docx` or PDF for text extraction.

## v11 — Unified JML / User Management lifecycle
- Operations menu renamed to Joiner / Mover / Leaver.
- JML CSV columns are normalized to a canonical lifecycle schema.
- Joiner/Mover/Leaver counters and type/date filters now use normalized values and ISO dates.
- JML CSV uploads synchronize into User Management: Joiner creates/activates directory users, Mover updates matching users, Leaver disables matching users.
- Matching uses Employee ID/Emp Code first, then email/username.
- JML-imported users without a supplied portal password are created as directory records with an unusable random password; an Admin can edit/set a password if portal login is needed.
- User Management form now includes Manager, Joining Date and Employee Status alongside employee identity fields.

## v18 FAQ live user context fix

- FAQ/Groq now receives the live server-side User Management directory on every chat request.
- Current portal totals (total, active, inactive, Admin, Viewer, Application Team, Audit Team and departments) come from `data/users.json` plus the primary `.env` administrator.
- Admin FAQ sessions also receive current non-sensitive user directory fields (name, employee code, username, department, role, status and designation) for user-specific questions.
- JML remains lifecycle-event history and is summarized separately as Joiner/Mover/Leaver counts.
- `/api/chat` now requires an authenticated session, preventing unauthenticated access to the AI proxy/live user context.

Example: if User Management shows 21 total users with 15 active and 6 inactive, asking `How many inactive users are there?` should answer `6` from the live directory instead of saying the data is unavailable.


## v20 Edit User Fix
- Fixed Save Changes failing after a successful PATCH because `appendLifecycleEvent()` was missing.
- User Management no longer re-imports old JML data after every page load/save; JML is only used to bootstrap an empty server user directory.
- Manual edits now persist and are marked as portal edits.
- Department changes create Mover events; Active→Inactive creates Leaver; Inactive→Active creates Joiner/reactivation event.
- Save button now shows Saving/Creating state and surfaces API errors without closing the drawer.


## v22 - Server-side operational data persistence
SOPs, ACM data, JML lifecycle history, Monthly Requests, Audit Evidence metadata/content and Application Handover tracking are now persisted in `DATA_DIR/app-data.json` instead of depending on browser localStorage. This makes the same data visible after login from another browser or private/incognito tab.

### One-time migration of existing browser data
Data uploaded in v21 or earlier exists only in the browser profile where it was uploaded. After upgrading to v22, first open the app once in that original normal browser profile and sign in with an account allowed to manage the data. v22 automatically migrates existing local data into the server store. After that, private/incognito windows and other browsers will read the same server data.

For Render, attach a persistent disk and set `DATA_DIR=/var/data` so `users.json` and `app-data.json` survive redeploys/restarts.
