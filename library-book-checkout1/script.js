const defaultBooks = [
    {
        id: 1,
        title: "Introduction to Programming",
        author: "John Smith",
        isbn: "9781234567890",
        available: true
    },
    {
        id: 2,
        title: "Database Management Systems",
        author: "Jane Williams",
        isbn: "9781234567891",
        available: true
    },
    {
        id: 3,
        title: "Information Security",
        author: "Robert Brown",
        isbn: "9781234567892",
        available: true
    },
    {
        id: 4,
        title: "Web Development Fundamentals",
        author: "Michael Johnson",
        isbn: "9781234567893",
        available: true
    },
    {
        id: 5,
        title: "The Great Gatsby",
        author: "F. Scott Fitzgerald",
        isbn: "9781234567894",
        available: true
    },
    {
        id: 6,
        title: "Pride and Prejudice",
        author: "Jane Austen",
        isbn: "9781234567895",
        available: true
    },
    {
        id: 7,
        title: "The Hobbit",
        author: "J.R.R. Tolkien",
        isbn: "9781234567896",
        available: true
    },
    {
        id: 8,
        title: "To Kill a Mockingbird",
        author: "Harper Lee",
        isbn: "9781234567897",
        available: true
    },
    {
        id: 9,
        title: "The Little Prince",
        author: "Antoine de Saint-Exupéry",
        isbn: "9781234567898",
        available: true
    },
    {
        id: 10,
        title: "1984",
        author: "George Orwell",
        isbn: "9781234567899",
        available: true
    }
];


const defaultUsers = [];

const defaultCheckouts = [];


// ========================================
// INITIALIZE BOOKS
// ========================================

let savedBooks = JSON.parse(
    localStorage.getItem("books")
) || [];


// Add only books that are missing

defaultBooks.forEach(defaultBook => {

    const existingBook = savedBooks.find(
        book => book.id === defaultBook.id
    );

    if (!existingBook) {

        savedBooks.push(defaultBook);

    }

});


localStorage.setItem(
    "books",
    JSON.stringify(savedBooks)
);


// ========================================
// INITIALIZE USERS
// ========================================

if (!localStorage.getItem("users")) {

    localStorage.setItem(
        "users",
        JSON.stringify(defaultUsers)
    );

}


// ========================================
// INITIALIZE CHECKOUTS
// ========================================

if (!localStorage.getItem("checkouts")) {

    localStorage.setItem(
        "checkouts",
        JSON.stringify(defaultCheckouts)
    );

}


// ========================================
// UPDATE DASHBOARD
// ========================================

function updateDashboard() {

    const books =
        JSON.parse(localStorage.getItem("books")) || [];

    const users =
        JSON.parse(localStorage.getItem("users")) || [];

    const checkouts =
        JSON.parse(localStorage.getItem("checkouts")) || [];


    // ========================================
    // BOOK COUNTS
    // ========================================

    const totalBooks =
        books.length;

    const availableBooks =
        books.filter(
            book => book.available
        ).length;

    const borrowedBooks =
        books.filter(
            book => !book.available
        ).length;

    const totalUsers =
        users.length;


    // ========================================
    // DISPLAY DASHBOARD COUNTS
    // ========================================

    const totalBooksElement =
        document.getElementById("totalBooks");

    const availableBooksElement =
        document.getElementById("availableBooks");

    const borrowedBooksElement =
        document.getElementById("borrowedBooks");

    const totalUsersElement =
        document.getElementById("totalUsers");


    if (totalBooksElement) {

        totalBooksElement.textContent =
            totalBooks;

    }


    if (availableBooksElement) {

        availableBooksElement.textContent =
            availableBooks;

    }


    if (borrowedBooksElement) {

        borrowedBooksElement.textContent =
            borrowedBooks;

    }


    if (totalUsersElement) {

        totalUsersElement.textContent =
            totalUsers;

    }


    // ========================================
    // RECENT CHECKOUTS TABLE
    // ========================================

    const table =
        document.getElementById("recentCheckouts");


    if (!table) {

        return;

    }


    table.innerHTML = "";


    // Students only see their own checkouts (staff see everything)

    const session =
        window.Security ? Security.getSession() : null;

    let visibleCheckouts = checkouts;

    if (session && !Security.isStaff(session)) {

        const me = Security.currentUserRecord(session, users);

        visibleCheckouts =
            me
                ? checkouts.filter(checkout => checkout.userId === me.id)
                : [];
    }


    visibleCheckouts.forEach(checkout => {

        const book =
            books.find(
                book => book.id === checkout.bookId
            );

        const user =
            users.find(
                user => user.id === checkout.userId
            );


        if (book && user) {

            const row =
                document.createElement("tr");


            const bookCell =
                document.createElement("td");

            bookCell.textContent =
                book.title;


            const userCell =
                document.createElement("td");

            userCell.textContent =
                user.name;


            const checkoutDateCell =
                document.createElement("td");

            checkoutDateCell.textContent =
                checkout.checkoutDate;


            const dueDateCell =
                document.createElement("td");

            dueDateCell.textContent =
                checkout.dueDate;


            row.appendChild(bookCell);

            row.appendChild(userCell);

            row.appendChild(checkoutDateCell);

            row.appendChild(dueDateCell);


            table.appendChild(row);

        }

    });

}


// ========================================
// RUN DASHBOARD UPDATE
// ========================================

updateDashboard();


console.log(
    "SCRIPT.JS IS RUNNING"
);