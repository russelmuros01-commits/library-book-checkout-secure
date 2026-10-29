// ========================================
// USER MANAGEMENT SYSTEM
// ========================================
// Staff only (Librarian / Admin). The page guard in security.js blocks
// Students before this file runs.

// ========================================
// GET USERS FROM LOCAL STORAGE
// ========================================

let users =
    JSON.parse(localStorage.getItem("users")) || [];


// ========================================
// DEFAULT USERS
// ========================================

if (users.length === 0) {

    users = [];

    localStorage.setItem(
        "users",
        JSON.stringify(users)
    );
}


// ========================================
// USER TABLE
// ========================================

const userTable =
    document.getElementById("userTable");


// ========================================
// DISPLAY USERS
// Only id, name, email and role are shown.
// Password hashes and recovery hashes are never displayed.
// ========================================

function displayUsers() {

    userTable.textContent = "";

    users.forEach(user => {

        const row =
            document.createElement("tr");

        [
            user.id,
            user.name,
            user.email,
            // Registered accounts are always Students
            user.role === "Librarian" || user.role === "Admin"
                ? user.role
                : "Student"
        ].forEach(value => {

            const cell = document.createElement("td");

            cell.textContent = value;

            row.appendChild(cell);
        });

        userTable.appendChild(row);
    });
}


// ========================================
// RUN DISPLAY
// ========================================

displayUsers();
