// ========================================
// BOOKS PAGE
// ========================================
// Book data is written with textContent (never innerHTML),
// so a malicious title or author can never run as code.

const books =
    JSON.parse(localStorage.getItem("books")) || [];

const bookTable =
    document.getElementById("bookTable");

const searchBook =
    document.getElementById("searchBook");


function addCell(row, text) {

    const cell = document.createElement("td");

    cell.textContent = text;

    row.appendChild(cell);

    return cell;
}

function displayBooks(bookList) {

    bookTable.textContent = "";

    bookList.forEach(book => {

        const row = document.createElement("tr");

        addCell(row, book.id);
        addCell(row, book.title);
        addCell(row, book.author);
        addCell(row, book.isbn);

        const statusCell = document.createElement("td");

        const status = document.createElement("span");

        status.className = book.available ? "available" : "borrowed";

        status.textContent = book.available ? "Available" : "Borrowed";

        statusCell.appendChild(status);

        row.appendChild(statusCell);

        bookTable.appendChild(row);
    });
}

searchBook.addEventListener("input", function () {

    const searchTerm =
        searchBook.value.toLowerCase();

    const filteredBooks = books.filter(book =>
        String(book.title).toLowerCase().includes(searchTerm) ||
        String(book.author).toLowerCase().includes(searchTerm)
    );

    displayBooks(filteredBooks);
});

displayBooks(books);
