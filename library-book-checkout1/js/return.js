// ========================================
// RETURN PAGE
// ========================================
// Role-Based Access Control:
//   Librarian / Admin : can see and return every borrowed book
//   Student           : can only see and return their OWN books

let books =
    JSON.parse(localStorage.getItem("books")) || [];

let users =
    JSON.parse(localStorage.getItem("users")) || [];

let checkouts =
    JSON.parse(localStorage.getItem("checkouts")) || [];

const returnTable =
    document.getElementById("returnTable");

const session = Security.getSession();


function reloadData() {

    books = JSON.parse(localStorage.getItem("books")) || [];

    users = JSON.parse(localStorage.getItem("users")) || [];

    checkouts = JSON.parse(localStorage.getItem("checkouts")) || [];
}

function canReturn(checkout) {

    if (!session) {
        return false;
    }

    if (Security.isStaff(session)) {
        return true;
    }

    const me = Security.currentUserRecord(session, users);

    return Boolean(me) && checkout.userId === me.id;
}

function sameCheckout(a, b) {

    return a.bookId === b.bookId &&
        a.userId === b.userId &&
        a.checkoutDate === b.checkoutDate;
}

function addCell(row, text) {

    const cell = document.createElement("td");

    cell.textContent = text;

    row.appendChild(cell);

    return cell;
}


// ========================================
// DISPLAY BORROWED BOOKS
// ========================================

function displayBorrowedBooks() {

    returnTable.textContent = "";

    checkouts.forEach(checkout => {

        if (!canReturn(checkout)) {
            return;
        }

        const book = books.find(
            book => book.id === checkout.bookId
        );

        const user = users.find(
            user => user.id === checkout.userId
        );

        if (!book || !user) {
            return;
        }

        const row = document.createElement("tr");

        addCell(row, book.title);
        addCell(row, user.name);
        addCell(row, checkout.checkoutDate);
        addCell(row, checkout.dueDate);

        const actionCell = document.createElement("td");

        const button = document.createElement("button");

        button.type = "button";
        button.className = "return-button";
        button.textContent = "Return";

        // addEventListener instead of an inline onclick (blocked by CSP)
        button.addEventListener("click", function () {
            returnBook(checkout);
        });

        actionCell.appendChild(button);

        row.appendChild(actionCell);

        returnTable.appendChild(row);
    });
}


// ========================================
// RETURN BOOK
// ========================================

function returnBook(selected) {

    // Always work with the latest saved data
    reloadData();

    const index = checkouts.findIndex(
        checkout => sameCheckout(checkout, selected)
    );

    if (index === -1) {

        alert("This checkout record no longer exists.");

        displayBorrowedBooks();

        return;
    }

    const checkout = checkouts[index];

    // Authorization is checked again at the moment of the action
    if (!canReturn(checkout)) {

        Security.audit("ACCESS_DENIED", "Tried to return a book that belongs to another user");

        alert("You can only return your own books.");

        return;
    }

    const book = books.find(
        book => book.id === checkout.bookId
    );

    if (!book) {
        return;
    }

    book.available = true;

    checkouts.splice(index, 1);

    localStorage.setItem("books", JSON.stringify(books));

    localStorage.setItem("checkouts", JSON.stringify(checkouts));

    Security.audit("RETURN", 'Returned "' + book.title + '" (book #' + book.id + ")");

    alert("Book returned successfully!");

    displayBorrowedBooks();
}


displayBorrowedBooks();
