# Library Book Checkout System (Secure Version)

## How to run
Open the folder in VS Code → right-click `index.html` → **Open with Live Server**.
(Use `http://127.0.0.1` / `localhost` or HTTPS. The Web Crypto API used for password hashing needs a secure context.)

## Demo accounts
| Role      | Email                  | Password            |
|-----------|------------------------|---------------------|
| Student   | jann@example.com       | `Jann@Lib2026!`     |
| Student   | russel@example.com     | `Russel@Lib2026!`   |
| Student   | ajay@example.com       | `Ajay@Lib2026!`     |
| Librarian | librarian@example.com  | `Librarian@Lib2026!`|
| Admin     | admin@example.com      | `Admin@Lib2026!`    |

Only salted hashes of these passwords exist in the source code (`js/security.js`).

## Input rules
* **Full name** – letters and spaces only (no numbers, no special characters). Enforced while typing and again on submit.
* **Password** – at least 8 characters, at least 1 number, at least 1 special character. Same rule on Create Account and Forgot Password.

## Security controls (maps to the STRIDE model in `documentation/phase-4`)
| STRIDE threat          | Control implemented                                                                                   |
|------------------------|--------------------------------------------------------------------------------------------------------|
| Spoofing               | PBKDF2-SHA256 (600,000 iterations) + unique 16-byte salt per password; generic login errors; lockout after 5 failed attempts (15 min); sessions in `sessionStorage` with 15-min idle and 8-hour absolute timeout |
| Tampering              | Output written with `textContent` (no `innerHTML`); strict Content-Security-Policy; roles assigned by code, never read from stored user data; stored data re-validated before use |
| Repudiation            | Audit log of logins, failures, lockouts, registrations, resets, checkouts, returns, denied access (Admin → *Audit Log*) |
| Information disclosure | Students only see their own checkouts/returns; Users page is staff-only; password and recovery hashes are never displayed; no account enumeration on login or reset |
| Denial of service      | Login and reset lockouts; PBKDF2 work factor is bounded when verifying stored hashes                    |
| Elevation of privilege | Role-Based Access Control: Student / Librarian / Admin, checked on page load **and** again at each action |

Password reset requires the one-time **recovery code** shown at account creation (stored hashed, replaced after every reset).

## Known limitation (by design of a front-end-only prototype)
All data lives in the browser (`localStorage`). Anyone with DevTools on that machine can still edit it.
These controls raise the cost of an attack and demonstrate the secure design, but true enforcement
(server-side validation, database, HTTPS, server-side authorization) belongs in the **Secure Redesign** (Phase 5).
