// ========================================
// SECURITY MODULE
// Library Book Checkout System
// ========================================
//
// Shared by every page. Load it BEFORE the page's own script.
//
//   1. Input validation        (full name, email, password policy)
//   2. Password hashing        (PBKDF2-SHA256 + unique salt, Web Crypto)
//   3. Brute-force protection  (temporary lockout after failed attempts)
//   4. Secure sessions         (idle timeout + absolute timeout)
//   5. Role-Based Access Control (Student / Librarian / Admin)
//   6. Account recovery        (one-time recovery code, stored hashed)
//   7. Audit logging           (who did what, and when)
//   8. Output sanitization     (escapeHTML / textContent helpers)
//
// NOTE: This is a front-end-only prototype. Every control here raises the
// cost of an attack, but anyone with DevTools can still edit browser
// storage. Real enforcement must live on a server (see Phase 5 docs).
// ========================================

(function (global) {

    "use strict";


    // ========================================
    // CONFIGURATION
    // ========================================

    const SCRIPT = document.currentScript;

    const ROOT_URL =
        SCRIPT && SCRIPT.src
            ? new URL("../", SCRIPT.src)
            : null;

        const CONFIG = Object.freeze({

        PBKDF2_ITERATIONS: 600000,   // OWASP recommendation for PBKDF2-HMAC-SHA256
        SALT_BYTES: 16,

        PASSWORD_MIN: 8,
        PASSWORD_MAX: 8,

        NAME_MIN: 2,
        NAME_MAX: 60,

        EMAIL_MAX: 254,

        MAX_FAILED_ATTEMPTS: 5,
        LOCKOUT_MS: 60 * 1000,               // 1 minute

        SESSION_IDLE_MS: 15 * 60 * 1000,     // logout after 15 min of inactivity
        SESSION_MAX_MS: 8 * 60 * 60 * 1000,  // logout after 8 hours no matter what

        AUDIT_MAX_ENTRIES: 1000,

        KEY_SESSION: "loggedInUser",
        KEY_USERS: "users",
        KEY_ATTEMPTS: "authAttempts",
        KEY_AUDIT: "auditLog"

    });

    const ROLES = Object.freeze(["Student", "Librarian", "Admin"]);

    const STAFF_ROLES = Object.freeze(["Librarian", "Admin"]);

    const RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 32 chars, no 0/O/1/I


    // ========================================
    // DEMO ACCOUNTS
    // Only salted hashes are stored. No plain-text passwords.
    // Roles for these accounts are fixed here, in code.
    // ========================================

    const DEMO_ACCOUNTS = Object.freeze([
        {
            email: "admin@123.gmail",
            name: "Administrator",
            role: "Admin",
            passwordHash: "pbkdf2-sha256$600000$+OLItJOvZO/ofr2CHQJPBQ==$C+hKr0XnbwUoX/pKCrGmRf+Urxhp/Nj7Fmu1XzhwdoU="
        }
    ]);

    // Used so that "unknown email" takes as long as "wrong password"
    const DUMMY_HASH =
        "pbkdf2-sha256$600000$fQcZMqCb9bgsrq6qYZdOBw==$5Hb93B6ywrU4y+SWkTMD4mtX6PqsLrGKd4rk86nAzDY=";


    // ========================================
    // SMALL HELPERS
    // ========================================

    function readJSON(storage, key, fallback) {

        try {

            const raw = storage.getItem(key);

            if (raw === null) {
                return fallback;
            }

            return JSON.parse(raw);

        } catch (error) {

            return fallback;

        }
    }

    function writeJSON(storage, key, value) {

        try {

            storage.setItem(key, JSON.stringify(value));

        } catch (error) {

            console.error("Storage write failed:", error);

        }
    }

    function sanitizeText(value) {

        return String(value === undefined || value === null ? "" : value)
            .replace(/[\u0000-\u001F\u007F]/g, "");

    }

    function escapeHTML(value) {

        return sanitizeText(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;")
            .replace(/`/g, "&#96;");

    }

    function normalizeEmail(value) {

        return sanitizeText(value).trim().toLowerCase();

    }

    function formatDuration(ms) {

        if (ms >= 60000) {

            const minutes = Math.ceil(ms / 60000);

            return minutes + (minutes === 1 ? " minute" : " minutes");

        }

        const seconds = Math.max(1, Math.ceil(ms / 1000));

        return seconds + (seconds === 1 ? " second" : " seconds");

    }

    function failure(message, extra) {

        return Object.assign({ ok: false, message: message }, extra || {});

    }


    // ========================================
    // 1. INPUT VALIDATION
    // ========================================

    // FULL NAME: letters and spaces only. No numbers, no special characters.
    // Unicode letters are allowed so names like "Peña" or "Muñoz" still work.

    const NAME_PATTERN = /^[\p{L}\p{M}]+(?: [\p{L}\p{M}]+)*$/u;

    function cleanName(value) {

        return sanitizeText(value)
            .normalize("NFC")
            .replace(/\s+/g, " ")
            .trim();

    }

    function validateName(raw) {

        const value = cleanName(raw);

        if (!value) {
            return { valid: false, value: value, message: "Full name is required." };
        }

        if (value.length < CONFIG.NAME_MIN) {
            return {
                valid: false,
                value: value,
                message: "Full name must be at least " + CONFIG.NAME_MIN + " letters."
            };
        }

        if (value.length > CONFIG.NAME_MAX) {
            return {
                valid: false,
                value: value,
                message: "Full name must not exceed " + CONFIG.NAME_MAX + " characters."
            };
        }

        if (!NAME_PATTERN.test(value)) {
            return {
                valid: false,
                value: value,
                message: "Full name can only contain letters and spaces. Numbers and special characters are not allowed."
            };
        }

        return { valid: true, value: value, message: "" };
    }

    // EMAIL

    const EMAIL_PATTERN =
        /^[^\s@<>()\[\]\\,;:"']+@[^\s@<>()\[\]\\,;:"']+\.[A-Za-z]{2,}$/;

    function validateEmail(raw) {

        const value = normalizeEmail(raw);

        if (!value) {
            return { valid: false, value: value, message: "Email is required." };
        }

        if (value.length > CONFIG.EMAIL_MAX || !EMAIL_PATTERN.test(value)) {
            return { valid: false, value: value, message: "Please enter a valid email address." };
        }

        return { valid: true, value: value, message: "" };
    }

    // PASSWORD: min 8 characters, at least 1 number, at least 1 special character

    function checkPassword(password) {

        const value = String(password === undefined || password === null ? "" : password);

        const length = value.length >= CONFIG.PASSWORD_MIN;
        const number = /[0-9]/.test(value);
        const special = /[^\p{L}\p{N}\s]/u.test(value);   // not a letter, digit or space
        const withinMax = value.length <= CONFIG.PASSWORD_MAX;

        return {
            length: length,
            number: number,
            special: special,
            withinMax: withinMax,
            all: length && number && special && withinMax
        };
    }

    function validatePassword(password) {

        const result = checkPassword(password);

        if (!result.withinMax) {
            return {
                valid: false,
                message: "Password must not exceed " + CONFIG.PASSWORD_MAX + " characters."
            };
        }

        if (result.all) {
            return { valid: true, message: "" };
        }

        const missing = [];

        if (!result.length) {
            missing.push("at least " + CONFIG.PASSWORD_MIN + " characters");
        }

        if (!result.number) {
            missing.push("at least 1 number");
        }

        if (!result.special) {
            missing.push("at least 1 special character (e.g. ! @ # $ % & *)");
        }

        return {
            valid: false,
            message: "Password must contain " + missing.join(", ") + "."
        };
    }


    // ========================================
    // 2. PASSWORD HASHING + SALTING (PBKDF2-SHA256)
    // Stored format: pbkdf2-sha256$iterations$salt$hash   (salt/hash = Base64)
    // ========================================

    const encoder = new TextEncoder();

    function toBase64(bytes) {

        let binary = "";

        bytes.forEach(function (byte) {
            binary += String.fromCharCode(byte);
        });

        return btoa(binary);
    }

    function fromBase64(text) {

        const binary = atob(text);
        const bytes = new Uint8Array(binary.length);

        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }

        return bytes;
    }

    function constantTimeEqual(a, b) {

        if (a.length !== b.length) {
            return false;
        }

        let difference = 0;

        for (let i = 0; i < a.length; i++) {
            difference |= a[i] ^ b[i];
        }

        return difference === 0;
    }

    function requireCrypto() {

        if (!global.crypto || !global.crypto.subtle) {

            throw new Error(
                "Secure cryptography is not available. " +
                "Open the system with Live Server (http://127.0.0.1) or HTTPS."
            );

        }
    }

    async function deriveBits(secret, salt, iterations) {

        requireCrypto();

        const key = await global.crypto.subtle.importKey(
            "raw",
            encoder.encode(String(secret).normalize("NFKC")),
            "PBKDF2",
            false,
            ["deriveBits"]
        );

        const bits = await global.crypto.subtle.deriveBits(
            { name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: iterations },
            key,
            256
        );

        return new Uint8Array(bits);
    }

    async function hashSecret(secret) {

        requireCrypto();

        const salt = global.crypto.getRandomValues(new Uint8Array(CONFIG.SALT_BYTES));

        const hash = await deriveBits(secret, salt, CONFIG.PBKDF2_ITERATIONS);

        return [
            "pbkdf2-sha256",
            CONFIG.PBKDF2_ITERATIONS,
            toBase64(salt),
            toBase64(hash)
        ].join("$");
    }

    async function verifySecret(secret, stored) {

        const parts = String(stored || "").split("$");

        if (parts.length !== 4 || parts[0] !== "pbkdf2-sha256") {
            return false;
        }

        const iterations = parseInt(parts[1], 10);

        // Bound the work factor so a tampered record cannot freeze the browser
        if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 2000000) {
            return false;
        }

        let salt;
        let expected;

        try {

            salt = fromBase64(parts[2]);
            expected = fromBase64(parts[3]);

        } catch (error) {

            return false;

        }

        const actual = await deriveBits(secret, salt, iterations);

        return constantTimeEqual(actual, expected);
    }

    function constantTimeStringEqual(a, b) {

        return constantTimeEqual(encoder.encode(String(a)), encoder.encode(String(b)));

    }


    // ========================================
    // RECOVERY CODE (one-time code for password reset)
    // ========================================

    function generateRecoveryCode() {

        const bytes = global.crypto.getRandomValues(new Uint8Array(16));

        let code = "";

        bytes.forEach(function (byte) {
            code += RECOVERY_ALPHABET[byte & 31];   // 256 % 32 === 0, so no bias
        });

        return code.match(/.{4}/g).join("-");
    }

    function normalizeRecoveryCode(value) {

        return String(value || "")
            .toUpperCase()
            .replace(/[^A-Z0-9]/g, "");

    }


    // ========================================
    // USER STORE
    // ========================================

    function getUsers() {

        const users = readJSON(global.localStorage, CONFIG.KEY_USERS, []);

        if (!Array.isArray(users)) {
            return [];
        }

        return users.filter(function (user) {
            return user && typeof user === "object";
        });
    }

    function saveUsers(users) {

        writeJSON(global.localStorage, CONFIG.KEY_USERS, users);

    }

    function findDemoAccount(email) {

        return DEMO_ACCOUNTS.find(function (account) {
            return account.email === email;
        }) || null;
    }

    function findStoredUser(email) {

        return getUsers().find(function (user) {
            return typeof user.email === "string" && user.email.toLowerCase() === email;
        }) || null;
    }

    function isEmailTaken(email) {

        const target = normalizeEmail(email);

        const storedAccount = getUsers().some(function (user) {
            return typeof user.email === "string" &&
                user.email.toLowerCase() === target &&
                (user.passwordHash || user.password);
        });

        return Boolean(findDemoAccount(target)) || storedAccount;
    }

    function nextUserId(users) {

        return users.reduce(function (max, user) {
            return Number.isFinite(user.id) && user.id > max ? user.id : max;
        }, 0) + 1;
    }

    // No default students. Every student account is created through the
    // Register page. ensureDefaultUsers() is kept so default accounts can be
    // added here later without touching the rest of the code.
    const DEFAULT_STUDENTS = Object.freeze([]);

    function ensureDefaultUsers() {

        const users = getUsers();

        let changed = false;

        DEFAULT_STUDENTS.forEach(function (student) {

            const exists = users.some(function (user) {
                return typeof user.email === "string" &&
                    user.email.toLowerCase() === student.email;
            });

            if (exists) {
                return;
            }

            const idTaken = users.some(function (user) {
                return user.id === student.id;
            });

            users.push({
                id: idTaken ? nextUserId(users) : student.id,
                name: student.name,
                email: student.email,
                role: "Student"
            });

            changed = true;
        });

        if (changed) {

            users.sort(function (a, b) {
                return (Number(a.id) || 0) - (Number(b.id) || 0);
            });

            saveUsers(users);
        }
    }


    // ========================================
    // 6. AUDIT LOG
    // ========================================

    function readSessionRaw() {

        const raw = readJSON(global.sessionStorage, CONFIG.KEY_SESSION, null);

        return raw && typeof raw === "object" ? raw : null;
    }

    function audit(action, detail, userOverride) {

        try {

            const session = readSessionRaw();

            const entry = {
                time: new Date().toISOString(),
                user: sanitizeText(
                    userOverride || (session && session.email) || "anonymous"
                ).slice(0, 100),
                action: sanitizeText(action).slice(0, 40),
                detail: sanitizeText(detail || "").slice(0, 200)
            };

            const log = readJSON(global.localStorage, CONFIG.KEY_AUDIT, []);

            const entries = Array.isArray(log) ? log : [];

            entries.push(entry);

            if (entries.length > CONFIG.AUDIT_MAX_ENTRIES) {
                entries.splice(0, entries.length - CONFIG.AUDIT_MAX_ENTRIES);
            }

            writeJSON(global.localStorage, CONFIG.KEY_AUDIT, entries);

        } catch (error) {

            console.error("Audit log failed:", error);

        }
    }

    function getAuditLog() {

        const log = readJSON(global.localStorage, CONFIG.KEY_AUDIT, []);

        return Array.isArray(log) ? log : [];
    }


    // ========================================
    // 3. BRUTE-FORCE PROTECTION
    // ========================================

    function loadAttempts() {

        const data = readJSON(global.localStorage, CONFIG.KEY_ATTEMPTS, {});

        return data && typeof data === "object" && !Array.isArray(data) ? data : {};
    }

    function saveAttempts(data) {

        writeJSON(global.localStorage, CONFIG.KEY_ATTEMPTS, data);

    }

    function getLockInfo(key) {

        const attempts = loadAttempts();
        const record = attempts[key];
        const now = Date.now();

        if (!record) {
            return { locked: false, remainingMs: 0 };
        }

        if (record.lockedUntil && record.lockedUntil > now) {
            return { locked: true, remainingMs: record.lockedUntil - now };
        }

        // Lock or old failures have expired
        if ((record.lockedUntil && record.lockedUntil <= now) ||
            (record.last && now - record.last > CONFIG.LOCKOUT_MS)) {

            delete attempts[key];
            saveAttempts(attempts);
        }

        return { locked: false, remainingMs: 0 };
    }

    function recordFailure(key) {

        const attempts = loadAttempts();
        const now = Date.now();

        const record = attempts[key] || { count: 0 };

        record.count = (record.count || 0) + 1;
        record.last = now;

        let locked = false;

        if (record.count >= CONFIG.MAX_FAILED_ATTEMPTS) {

            record.lockedUntil = now + CONFIG.LOCKOUT_MS;
            record.count = 0;
            locked = true;

        }

        attempts[key] = record;

        saveAttempts(attempts);

        return {
            locked: locked,
            remainingMs: locked ? CONFIG.LOCKOUT_MS : 0,
            attemptsLeft: locked ? 0 : CONFIG.MAX_FAILED_ATTEMPTS - record.count
        };
    }

    function clearFailures(key) {

        const attempts = loadAttempts();

        if (attempts[key]) {

            delete attempts[key];
            saveAttempts(attempts);

        }
    }

    function lockMessage(remainingMs) {

        return "Too many failed attempts. Please try again in " +
            formatDuration(remainingMs) + ".";

    }


    // ========================================
    // 4. SESSION MANAGEMENT
    // Stored in sessionStorage: cleared when the tab/browser is closed.
    // ========================================

    function clearSession() {

        try {

            global.sessionStorage.removeItem(CONFIG.KEY_SESSION);

        } catch (error) { /* ignore */ }
    }

    function createSession(account) {

        const now = Date.now();

        const session = {
            name: sanitizeText(account.name),
            email: normalizeEmail(account.email),
            role: ROLES.indexOf(account.role) !== -1 ? account.role : "Student",
            issuedAt: now,
            lastActive: now
        };

        writeJSON(global.sessionStorage, CONFIG.KEY_SESSION, session);

        return session;
    }

    function getSession() {

        const raw = readSessionRaw();

        if (!raw) {
            return null;
        }

        const validShape =
            typeof raw.name === "string" &&
            typeof raw.email === "string" &&
            ROLES.indexOf(raw.role) !== -1 &&
            Number.isFinite(raw.issuedAt) &&
            Number.isFinite(raw.lastActive);

        if (!validShape) {

            clearSession();

            return null;
        }

        const now = Date.now();

        if (now - raw.lastActive > CONFIG.SESSION_IDLE_MS ||
            now - raw.issuedAt > CONFIG.SESSION_MAX_MS) {

            audit("SESSION_EXPIRED", "Session timed out", raw.email);

            clearSession();

            return null;
        }

        return raw;
    }

    function touchSession() {

        const session = getSession();

        if (!session) {
            return;
        }

        session.lastActive = Date.now();

        writeJSON(global.sessionStorage, CONFIG.KEY_SESSION, session);
    }

    function isStaff(session) {

        return Boolean(session) && STAFF_ROLES.indexOf(session.role) !== -1;

    }

    function currentUserRecord(session, users) {

        if (!session || !Array.isArray(users)) {
            return null;
        }

        return users.find(function (user) {
            return user && typeof user.email === "string" &&
                user.email.toLowerCase() === session.email;
        }) || null;
    }

    function pageUrl(path) {

        if (ROOT_URL) {
            return new URL(path, ROOT_URL).href;
        }

        return path;
    }

    function logout(reason) {

        const session = readSessionRaw();

        audit(reason || "LOGOUT", "User signed out", session && session.email);

        clearSession();

        global.location.replace(pageUrl("pages/login.html"));
    }


    // ========================================
    // 5. PAGE GUARD + ROLE-BASED ACCESS CONTROL
    // Usage: <script src="../js/security.js" data-guard data-roles="Librarian,Admin">
    // ========================================

    function onReady(callback) {

        if (document.readyState === "loading") {

            document.addEventListener("DOMContentLoaded", callback);

        } else {

            callback();

        }
    }

    function enhanceNavigation(session) {

        const nav = document.querySelector("nav");

        if (!nav) {
            return;
        }

        // Students cannot see staff-only pages
        if (!isStaff(session)) {

            nav.querySelectorAll('a[href$="users.html"]').forEach(function (link) {
                link.remove();
            });

        }

        // Admin-only: Audit Log
        if (session.role === "Admin" && !nav.querySelector('a[href$="audit-log.html"]')) {

            const link = document.createElement("a");

            link.href = pageUrl("pages/audit-log.html");
            link.textContent = "Audit Log";

            if (/audit-log\.html$/.test(global.location.pathname)) {
                link.className = "active";
            }

            nav.insertBefore(link, nav.querySelector("#logoutButton"));
        }
    }

    function bindLogoutButton() {

        const button = document.getElementById("logoutButton");

        if (!button) {
            return;
        }

        button.addEventListener("click", function () {

            if (!global.confirm("Are you sure you want to logout?")) {
                return;
            }

            logout("LOGOUT");
        });
    }

    function startActivityMonitor() {

        let lastTouch = 0;

        function onActivity() {

            const now = Date.now();

            if (now - lastTouch > 10000) {

                lastTouch = now;

                touchSession();
            }
        }

        ["click", "keydown", "mousemove", "scroll", "touchstart"].forEach(function (name) {
            document.addEventListener(name, onActivity, { passive: true });
        });

        global.setInterval(function () {

            if (!getSession()) {

                global.alert("Your session has expired. Please login again.");

                global.location.replace(pageUrl("pages/login.html"));
            }

        }, 15000);

        // Back/forward cache: re-check when a protected page is restored
        global.addEventListener("pageshow", function (event) {

            if (event.persisted && !getSession()) {
                global.location.replace(pageUrl("pages/login.html"));
            }
        });
    }

    function guardPage(allowedRoles) {

        // Hide the page until we know the visitor is allowed to see it
        document.documentElement.style.visibility = "hidden";

        const session = getSession();

        if (!session) {

            global.location.replace(pageUrl("pages/login.html"));

            return null;
        }

        if (allowedRoles.length > 0 && allowedRoles.indexOf(session.role) === -1) {

            audit("ACCESS_DENIED", "Blocked from " + global.location.pathname);

            global.alert("You do not have permission to access this page.");

            global.location.replace(pageUrl("index.html"));

            return null;
        }

        touchSession();

        onReady(function () {

            enhanceNavigation(session);

            bindLogoutButton();

            startActivityMonitor();

            document.documentElement.style.visibility = "";
        });

        return session;
    }


    // ========================================
    // ACCOUNT ACTIONS
    // ========================================

    async function registerUser(input) {

        const nameCheck = validateName(input.name);
        const emailCheck = validateEmail(input.email);
        const passwordCheck = validatePassword(input.password);

        if (!nameCheck.valid) {
            return failure(nameCheck.message, { field: "name" });
        }

        if (!emailCheck.valid) {
            return failure(emailCheck.message, { field: "email" });
        }

        if (!passwordCheck.valid) {
            return failure(passwordCheck.message, { field: "password" });
        }

        if (input.password !== input.confirmPassword) {
            return failure("Passwords do not match.", { field: "confirmPassword" });
        }

        if (isEmailTaken(emailCheck.value)) {
            return failure("An account with this email already exists.", { field: "email" });
        }

        const passwordHash = await hashSecret(input.password);

        const recoveryCode = generateRecoveryCode();

        const recoveryHash = await hashSecret(normalizeRecoveryCode(recoveryCode));

        // Re-read after the awaits (guards against a double submit)
        const users = getUsers();

        if (isEmailTaken(emailCheck.value)) {
            return failure("An account with this email already exists.", { field: "email" });
        }

        users.push({
            id: nextUserId(users),
            name: nameCheck.value,
            email: emailCheck.value,
            role: "Student",               // the system assigns roles, never the form
            passwordHash: passwordHash,
            recoveryHash: recoveryHash,
            createdAt: new Date().toISOString()
        });

        saveUsers(users);

        audit("REGISTER", "New student account created", emailCheck.value);

        return { ok: true, recoveryCode: recoveryCode };
    }

    function findLoginAccount(email) {

        // Demo/system accounts always win, so they cannot be overridden via storage
        const demo = findDemoAccount(email);

        if (demo) {
            return { source: "demo", account: demo };
        }

        const stored = findStoredUser(email);

        if (stored && (stored.passwordHash || typeof stored.password === "string")) {

            return {
                source: "stored",
                account: {
                    email: stored.email,
                    name: stored.name,
                    role: "Student",        // registered accounts are always Students
                    passwordHash: stored.passwordHash,
                    legacyPassword: stored.password
                }
            };
        }

        return null;
    }

    async function login(emailInput, password) {

        const email = normalizeEmail(emailInput).slice(0, CONFIG.EMAIL_MAX);

        const lockKey = "login:" + email;

        const lock = getLockInfo(lockKey);

        if (lock.locked) {

            audit("LOGIN_BLOCKED", "Locked out", email);

            return failure(lockMessage(lock.remainingMs), { locked: true });
        }

        const found = EMAIL_PATTERN.test(email) ? findLoginAccount(email) : null;

        let valid = false;

        if (found && found.account.passwordHash) {

            valid = await verifySecret(password, found.account.passwordHash);

        } else if (found && typeof found.account.legacyPassword === "string") {

            // Old plain-text account: verify once, then upgrade to a salted hash
            valid = constantTimeStringEqual(found.account.legacyPassword, password);

            if (valid) {

                const upgradedHash = await hashSecret(password);

                const users = getUsers();

                const target = users.find(function (user) {
                    return typeof user.email === "string" && user.email.toLowerCase() === email;
                });

                if (target) {

                    target.passwordHash = upgradedHash;

                    delete target.password;

                    saveUsers(users);

                    audit("PASSWORD_UPGRADED", "Plain-text password replaced with a salted hash", email);
                }
            }

        } else {

            await verifySecret(password, DUMMY_HASH);

        }

        if (!valid) {

            const info = recordFailure(lockKey);

            audit("LOGIN_FAILED", "Invalid credentials", email);

            if (info.locked) {

                audit("ACCOUNT_LOCKED", "Too many failed logins", email);

                return failure(lockMessage(info.remainingMs), { locked: true });
            }

            return failure(
                "Invalid email or password. " + info.attemptsLeft +
                (info.attemptsLeft === 1 ? " attempt" : " attempts") + " left."
            );
        }

        clearFailures(lockKey);

        const session = createSession(found.account);

        audit("LOGIN_SUCCESS", "Signed in as " + session.role, session.email);

        return { ok: true, session: session };
    }

    async function resetPassword(input) {

        const emailCheck = validateEmail(input.email);

        if (!emailCheck.valid) {
            return failure(emailCheck.message, { field: "email" });
        }

        const code = normalizeRecoveryCode(input.recoveryCode);

        if (code.length !== 16) {
            return failure("Please enter your 16-character recovery code.", { field: "recoveryCode" });
        }

        const passwordCheck = validatePassword(input.newPassword);

        if (!passwordCheck.valid) {
            return failure(passwordCheck.message, { field: "newPassword" });
        }

        if (input.newPassword !== input.confirmPassword) {
            return failure("Passwords do not match.", { field: "confirmPassword" });
        }

        const lockKey = "reset:" + emailCheck.value;

        const lock = getLockInfo(lockKey);

        if (lock.locked) {
            return failure(lockMessage(lock.remainingMs), { locked: true });
        }

        const users = getUsers();

        const user = users.find(function (item) {
            return typeof item.email === "string" &&
                item.email.toLowerCase() === emailCheck.value &&
                typeof item.recoveryHash === "string" &&
                !findDemoAccount(emailCheck.value);
        });

        let codeIsValid = false;

        if (user) {
            codeIsValid = await verifySecret(code, user.recoveryHash);
        } else {
            await verifySecret(code, DUMMY_HASH);
        }

        if (!codeIsValid) {

            const info = recordFailure(lockKey);

            audit("RESET_FAILED", "Invalid recovery code", emailCheck.value);

            // Same message whether the email exists or not (no account enumeration)
            return failure(
                info.locked
                    ? lockMessage(info.remainingMs)
                    : "Invalid email or recovery code.",
                { locked: info.locked }
            );
        }

        if (user.passwordHash && await verifySecret(input.newPassword, user.passwordHash)) {
            return failure(
                "Your new password must be different from your current password.",
                { field: "newPassword" }
            );
        }

        const newCode = generateRecoveryCode();

        user.passwordHash = await hashSecret(input.newPassword);
        user.recoveryHash = await hashSecret(normalizeRecoveryCode(newCode));   // codes are single-use
        user.passwordChangedAt = new Date().toISOString();

        delete user.password;

        saveUsers(users);

        clearFailures(lockKey);
        clearFailures("login:" + emailCheck.value);

        audit("PASSWORD_RESET", "Password reset with recovery code", emailCheck.value);

        return { ok: true, recoveryCode: newCode };
    }


    // ========================================
    // FORM HELPERS (used by Register and Forgot Password pages)
    // ========================================

    // Blocks numbers and special characters while the user types or pastes
    function attachNameFilter(input, messageElement) {

        input.addEventListener("input", function (event) {

            if (event.isComposing) {
                return;
            }

            const original = input.value;

            const cleaned = original
                .normalize("NFC")
                .replace(/[^\p{L}\p{M}\s]/gu, "")
                .replace(/\s+/g, " ")
                .replace(/^\s+/, "");

            if (cleaned !== original) {

                input.value = cleaned;

                if (messageElement) {
                    messageElement.textContent =
                        "Only letters and spaces are allowed in the full name.";
                }

            } else if (messageElement) {

                messageElement.textContent = "";

            }
        });
    }

    // Live checklist: turns each rule green as it is satisfied
    function attachPasswordChecklist(input, listElement) {

        if (!listElement) {
            return;
        }

        function update() {

            const result = checkPassword(input.value);

            listElement.querySelectorAll("li[data-rule]").forEach(function (item) {

                item.classList.toggle("met", Boolean(result[item.getAttribute("data-rule")]));

            });
        }

        input.addEventListener("input", update);

        update();
    }

    function setMessage(element, text, type) {

        if (!element) {
            return;
        }

        element.textContent = text;

        element.className = "login-message" + (type ? " " + type : "");
    }


    // Adds a "Show password" checkbox under every password field
    function addShowPasswordToggles() {

        document.querySelectorAll('input[type="password"]').forEach(function (input) {

            const label = document.createElement("label");

            label.className = "show-password";

            label.style.cssText =
                "display:flex;align-items:center;gap:6px;margin-top:6px;" +
                "font-size:14px;font-weight:normal;cursor:pointer;";

            const box = document.createElement("input");

            box.type = "checkbox";

            box.style.width = "auto";

            box.addEventListener("change", function () {
                input.type = box.checked ? "text" : "password";
            });

            label.appendChild(box);

            label.appendChild(document.createTextNode("Show password"));

            input.insertAdjacentElement("afterend", label);
        });
    }


    // ========================================
    // PUBLIC API
    // ========================================

    global.Security = Object.freeze({

        CONFIG: CONFIG,
        ROLES: ROLES,

        // validation
        validateName: validateName,
        validateEmail: validateEmail,
        validatePassword: validatePassword,
        checkPassword: checkPassword,

        // hashing
        hashSecret: hashSecret,
        verifySecret: verifySecret,

        // accounts
        registerUser: registerUser,
        login: login,
        resetPassword: resetPassword,
        isEmailTaken: isEmailTaken,

        // session + access control
        getSession: getSession,
        isStaff: isStaff,
        currentUserRecord: currentUserRecord,
        logout: logout,
        pageUrl: pageUrl,

        // audit
        audit: audit,
        getAuditLog: getAuditLog,

        // output safety
        escapeHTML: escapeHTML,
        sanitizeText: sanitizeText,

        // form helpers
        attachNameFilter: attachNameFilter,
        attachPasswordChecklist: attachPasswordChecklist,
        setMessage: setMessage

    });


    // ========================================
    // AUTO-RUN
    // ========================================

    // Remove any old, unsafe session that was kept in localStorage
    try {

        global.localStorage.removeItem("loggedInUser");

    } catch (error) { /* ignore */ }

    try {

        ensureDefaultUsers();

    } catch (error) {

        console.error("Unable to prepare default users:", error);

    }

    onReady(addShowPasswordToggles);

    if (SCRIPT && SCRIPT.hasAttribute("data-guard")) {

        const roles = (SCRIPT.getAttribute("data-roles") || "")
            .split(",")
            .map(function (role) { return role.trim(); })
            .filter(Boolean);

        guardPage(roles);
    }

})(window);