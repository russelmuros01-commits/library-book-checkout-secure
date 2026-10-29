// ========================================
// CREATE ACCOUNT / REGISTER SYSTEM
// ========================================
// Rules enforced here (and again inside security.js):
//   - Full name : letters and spaces only (no numbers / special characters)
//   - Password  : at least 8 characters, 1 number, 1 special character
//   - Password is stored as a salted PBKDF2 hash, never as plain text

const registerForm = document.getElementById("registerForm");
const registerMessage = document.getElementById("registerMessage");
const registerButton = registerForm.querySelector('button[type="submit"]');

const nameInput = document.getElementById("name");
const passwordInput = document.getElementById("password");

const recoveryBox = document.getElementById("recoveryBox");
const recoveryCodeText = document.getElementById("recoveryCode");
const copyRecoveryButton = document.getElementById("copyRecoveryButton");
const recoverySaved = document.getElementById("recoverySaved");
const continueButton = document.getElementById("continueToLogin");


// ========================================
// LIVE INPUT PROTECTION
// ========================================

// Numbers and special characters cannot be typed or pasted into the name
Security.attachNameFilter(
    nameInput,
    document.getElementById("nameError")
);

// Password checklist turns green as each rule is met
Security.attachPasswordChecklist(
    passwordInput,
    document.getElementById("passwordRules")
);


// ========================================
// REGISTER FUNCTION
// ========================================

registerForm.addEventListener("submit", async function (event) {

    event.preventDefault();

    registerButton.disabled = true;

    Security.setMessage(registerMessage, "Creating your account...", "");

    try {

        const result = await Security.registerUser({

            name: nameInput.value,

            email: document.getElementById("email").value,

            password: passwordInput.value,

            confirmPassword:
                document.getElementById("confirmPassword").value

        });


        // ========================================
        // VALIDATION / DUPLICATE ERRORS
        // ========================================

        if (!result.ok) {

            Security.setMessage(registerMessage, result.message, "error");

            registerButton.disabled = false;

            return;
        }


        // ========================================
        // SUCCESS: SHOW ONE-TIME RECOVERY CODE
        // ========================================

        registerForm.reset();

        registerForm.hidden = true;

        recoveryCodeText.textContent = result.recoveryCode;

        recoveryBox.hidden = false;

    } catch (error) {

        console.error(error);

        Security.setMessage(
            registerMessage,
            error && error.message
                ? error.message
                : "Something went wrong. Please try again.",
            "error"
        );

        registerButton.disabled = false;
    }

});


// ========================================
// RECOVERY CODE CONTROLS
// ========================================

copyRecoveryButton.addEventListener("click", async function () {

    try {

        await navigator.clipboard.writeText(recoveryCodeText.textContent);

        copyRecoveryButton.textContent = "Copied!";

    } catch (error) {

        copyRecoveryButton.textContent = "Select the code and copy it manually";

    }
});

recoverySaved.addEventListener("change", function () {

    continueButton.disabled = !recoverySaved.checked;

});

continueButton.addEventListener("click", function () {

    window.location.href = "login.html";

});
