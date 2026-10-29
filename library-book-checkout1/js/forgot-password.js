// ========================================
// FORGOT PASSWORD SYSTEM
// ========================================
// A password can only be reset with the one-time RECOVERY CODE that was
// shown when the account was created. Knowing the email alone is not enough.
// A wrong code never reveals whether the email exists, and repeated wrong
// codes temporarily lock the reset.

const forgotPasswordForm =
    document.getElementById("forgotPasswordForm");

const forgotMessage =
    document.getElementById("forgotMessage");

const resetButton =
    forgotPasswordForm.querySelector('button[type="submit"]');

const newPasswordInput =
    document.getElementById("newPassword");

const recoveryBox = document.getElementById("recoveryBox");
const recoveryCodeText = document.getElementById("recoveryCode");
const copyRecoveryButton = document.getElementById("copyRecoveryButton");
const recoverySaved = document.getElementById("recoverySaved");
const continueButton = document.getElementById("continueToLogin");


// Live password checklist

Security.attachPasswordChecklist(
    newPasswordInput,
    document.getElementById("passwordRules")
);


// ========================================
// RESET PASSWORD FUNCTION
// ========================================

forgotPasswordForm.addEventListener("submit", async function (event) {

    event.preventDefault();

    resetButton.disabled = true;

    Security.setMessage(forgotMessage, "Checking your recovery code...", "");

    try {

        const result = await Security.resetPassword({

            email:
                document.getElementById("resetEmail").value,

            recoveryCode:
                document.getElementById("recoveryCodeInput").value,

            newPassword:
                newPasswordInput.value,

            confirmPassword:
                document.getElementById("confirmPassword").value

        });


        if (!result.ok) {

            Security.setMessage(forgotMessage, result.message, "error");

            resetButton.disabled = false;

            return;
        }


        // ========================================
        // SUCCESS: SHOW A NEW ONE-TIME RECOVERY CODE
        // ========================================

        forgotPasswordForm.reset();

        forgotPasswordForm.hidden = true;

        recoveryCodeText.textContent = result.recoveryCode;

        recoveryBox.hidden = false;

    } catch (error) {

        console.error(error);

        Security.setMessage(
            forgotMessage,
            error && error.message
                ? error.message
                : "Something went wrong. Please try again.",
            "error"
        );

        resetButton.disabled = false;
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
