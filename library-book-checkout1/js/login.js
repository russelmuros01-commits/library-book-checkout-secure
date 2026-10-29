// ========================================
// LOGIN SYSTEM
// ========================================
// All credential checking happens in security.js:
//   - passwords are verified against salted PBKDF2 hashes
//   - failed attempts are counted and the account is temporarily locked
//   - the error message never says whether the email or the password was wrong

const loginForm = document.getElementById("loginForm");
const loginMessage = document.getElementById("loginMessage");
const loginButton = loginForm.querySelector('button[type="submit"]');


loginForm.addEventListener("submit", async function (event) {

    event.preventDefault();

    const email =
        document.getElementById("email").value;

    const passwordInput =
        document.getElementById("password");

    const password =
        passwordInput.value;


    // Block double-clicks while the password is being checked

    loginButton.disabled = true;

    Security.setMessage(loginMessage, "Signing in...", "");


    try {

        const result =
            await Security.login(email, password);


        // ========================================
        // INVALID LOGIN / LOCKED OUT
        // ========================================

        if (!result.ok) {

            Security.setMessage(loginMessage, result.message, "error");

            passwordInput.value = "";

            loginButton.disabled = false;

            return;
        }


        // ========================================
        // SUCCESS
        // ========================================

        Security.setMessage(
            loginMessage,
            "Login successful. Welcome, " + result.session.name + "!",
            "success"
        );

        setTimeout(function () {

            window.location.href = Security.pageUrl("index.html");

        }, 800);

    } catch (error) {

        console.error(error);

        Security.setMessage(
            loginMessage,
            error && error.message
                ? error.message
                : "Something went wrong. Please try again.",
            "error"
        );

        loginButton.disabled = false;
    }

});
