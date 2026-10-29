// ========================================
// LIBRARY BOOK CHECKOUT SYSTEM
// ========================================
// Role-Based Access Control:
//   Librarian / Admin : can check out a book for any user
//   Student           : can only check out for their OWN account
// Every checkout is written to the audit log.

// ========================================
// BOOK DATA
// ========================================

let books = JSON.parse(localStorage.getItem("books")) || [
    { id: 1, title: "Introduction to Programming", author: "John Smith", isbn: "9781234567890", available: true },
    { id: 2, title: "Database Management Systems", author: "Jane Williams", isbn: "9781234567891", available: true },
    { id: 3, title: "Information Security", author: "Robert Brown", isbn: "9781234567892", available: true },
    { id: 4, title: "Web Development Fundamentals", author: "Michael Johnson", isbn: "9781234567893", available: true },
    { id: 5, title: "Computer Networks", author: "David Wilson", isbn: "9781234567894", available: true },
    { id: 6, title: "Operating Systems", author: "Sarah Davis", isbn: "9781234567895", available: true },
    { id: 7, title: "Data Structures and Algorithms", author: "James Miller", isbn: "9781234567896", available: true },
    { id: 8, title: "Software Engineering", author: "Emily Anderson", isbn: "9781234567897", available: true },
    { id: 9, title: "Cybersecurity Fundamentals", author: "Daniel Thomas", isbn: "9781234567898", available: true },
    { id: 10, title: "Human Computer Interaction", author: "Olivia Moore", isbn: "9781234567899", available: true }
];

// Save books
localStorage.setItem("books", JSON.stringify(books));


// ========================================
// DEFAULT USERS
// ========================================

let users = JSON.parse(localStorage.getItem("users")) || [];


// ========================================
// CHECKOUT DATA
// ========================================

let checkouts = JSON.parse(
    localStorage.getItem("checkouts")
) || [];

// Save checkout records
localStorage.setItem("checkouts", JSON.stringify(checkouts));


// ========================================
// GET HTML ELEMENTS
// ========================================

const userSelect = document.getElementById("userSelect");
const bookSelect = document.getElementById("bookSelect");
const checkoutForm = document.getElementById("checkoutForm");
const checkoutTable = document.getElementById("checkoutTable");


// ========================================
// CURRENT LOGGED-IN USER (from the secure session)
// ========================================

const session = Security.getSession();

const isStaff = Security.isStaff(session);

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;


// ========================================
// LOAD USERS INTO SELECT
// ========================================

function loadUsers() {

    if (!userSelect) {
        return;
    }

    userSelect.textContent = "";

    const placeholder = document.createElement("option");

    placeholder.value = "";
    placeholder.textContent = "-- Select User --";

    userSelect.appendChild(placeholder);

    if (!session) {
        return;
    }

    // LIBRARIAN / ADMIN: every user
    if (isStaff) {

        users.forEach(user => {

            const option = document.createElement("option");

            option.value = user.id;

            option.textContent =
                `${user.name} (${user.role === "Librarian" || user.role === "Admin" ? user.role : "Student"})`;

            userSelect.appendChild(option);
        });

        return;
    }

    // STUDENT: only themselves
    const currentUser = Security.currentUserRecord(session, users);

    if (currentUser) {

        const option = document.createElement("option");

        option.value = currentUser.id;

        option.textContent = currentUser.name;

        userSelect.appendChild(option);

        // Automatically select logged-in student
        userSelect.value = currentUser.id;
    }
}


// ========================================
// LOAD ALL AVAILABLE BOOKS
// ========================================

function loadAvailableBooks() {

    if (!bookSelect) {
        return;
    }

    bookSelect.textContent = "";

    const placeholder = document.createElement("option");

    placeholder.value = "";
    placeholder.textContent = "-- Select Book --";

    bookSelect.appendChild(placeholder);

    // Get updated book data
    try {

        const storedBooks = JSON.parse(localStorage.getItem("books"));

        if (Array.isArray(storedBooks) && storedBooks.length > 0) {
            books = storedBooks;
        }

    } catch (error) {

        console.error("Unable to load books:", error);

    }

    // Display only available books
    books
        .filter(book => book.available === true)
        .forEach(book => {

            const option = document.createElement("option");

            option.value = book.id;

            option.textContent = `${book.title} - ${book.author}`;

            bookSelect.appendChild(option);
        });
}


// ========================================
// DISPLAY CHECKOUT RECORDS
// Students only see their own records.
// ========================================

function displayCheckouts() {

    if (!checkoutTable) {
        return;
    }

    checkoutTable.textContent = "";

    // Reload latest data
    try {

        const storedCheckouts = JSON.parse(localStorage.getItem("checkouts"));

        if (Array.isArray(storedCheckouts)) {
            checkouts = storedCheckouts;
        }

    } catch (error) {

        console.error("Unable to load checkouts:", error);

    }

    const me = Security.currentUserRecord(session, users);

    checkouts.forEach(checkout => {

        if (!isStaff && !(me && checkout.userId === me.id)) {
            return;
        }

        const book = books.find(book => book.id === checkout.bookId);

        const user = users.find(user => user.id === checkout.userId);

        if (!book || !user) {
            return;
        }

        const row = document.createElement("tr");

        [book.title, user.name, checkout.checkoutDate, checkout.dueDate].forEach(value => {

            const cell = document.createElement("td");

            cell.textContent = value;

            row.appendChild(cell);
        });

        checkoutTable.appendChild(row);
    });
}


// ========================================
// CHECKOUT BOOK
// ========================================

if (checkoutForm) {

    checkoutForm.addEventListener("submit", function (event) {

        event.preventDefault();

        // Session may have expired while the page was open
        if (!Security.getSession()) {

            alert("Your session has expired. Please login again.");

            window.location.replace(Security.pageUrl("pages/login.html"));

            return;
        }

        // ========================================
        // GET FORM VALUES
        // ========================================

        const userId = Number(userSelect.value);

        const bookId = Number(bookSelect.value);

        const checkoutDate = document.getElementById("checkoutDate").value;

        const dueDate = document.getElementById("dueDate").value;


        // ========================================
        // VALIDATE INPUT
        // ========================================

        if (!userId) {
            alert("Please select a user.");
            return;
        }

        if (!bookId) {
            alert("Please select a book.");
            return;
        }

        if (!ISO_DATE.test(checkoutDate)) {
            alert("Please select a checkout date.");
            return;
        }

        if (!ISO_DATE.test(dueDate)) {
            alert("Please select a due date.");
            return;
        }

        if (dueDate < checkoutDate) {
            alert("Due date cannot be earlier than the checkout date.");
            return;
        }


        // ========================================
        // VALIDATE USER AND BOOK (against stored data, not the form)
        // ========================================

        const targetUser = users.find(user => user.id === userId);

        if (!targetUser) {
            alert("Selected user does not exist.");
            return;
        }

        const book = books.find(book => book.id === bookId);

        if (!book || book.available !== true) {

            alert("This book is not available.");

            loadAvailableBooks();

            return;
        }


        // ========================================
        // AUTHORIZATION CHECK (RBAC)
        // ========================================

        if (!isStaff) {

            const currentUser = Security.currentUserRecord(session, users);

            if (!currentUser || userId !== currentUser.id) {

                Security.audit(
                    "ACCESS_DENIED",
                    "Tried to check out a book for another user"
                );

                alert("You can only checkout a book for your own account.");

                return;
            }
        }


        // ========================================
        // CREATE CHECKOUT RECORD
        // ========================================

        checkouts.push({
            bookId: bookId,
            userId: userId,
            checkoutDate: checkoutDate,
            dueDate: dueDate
        });


        // ========================================
        // MARK BOOK AS UNAVAILABLE + SAVE
        // ========================================

        book.available = false;

        localStorage.setItem("books", JSON.stringify(books));

        localStorage.setItem("checkouts", JSON.stringify(checkouts));


        // ========================================
        // AUDIT TRAIL (non-repudiation)
        // ========================================

        Security.audit(
            "CHECKOUT",
            `"${book.title}" (book #${book.id}) checked out for ${targetUser.name}, due ${dueDate}`
        );


        // ========================================
        // SUCCESS + REFRESH
        // ========================================

        alert("Book checked out successfully!");

        checkoutForm.reset();

        loadUsers();

        loadAvailableBooks();

        displayCheckouts();
    });
}


// ========================================
// INITIAL LOAD
// ========================================

loadUsers();

loadAvailableBooks();

displayCheckouts();