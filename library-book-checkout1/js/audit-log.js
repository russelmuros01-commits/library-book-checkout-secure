// ========================================
// AUDIT LOG PAGE (Admin only)
// ========================================
// Read-only. Shows who did what and when. Entries are written with
// textContent, so nothing in the log can run as code.

const auditTable = document.getElementById("auditTable");
const auditCount = document.getElementById("auditCount");

function displayAuditLog() {

    const entries = Security.getAuditLog().slice().reverse();   // newest first

    auditTable.textContent = "";

    auditCount.textContent =
        entries.length + (entries.length === 1 ? " entry" : " entries");

    entries.forEach(entry => {

        const row = document.createElement("tr");

        const time = new Date(entry.time);

        [
            isNaN(time.getTime()) ? String(entry.time) : time.toLocaleString(),
            entry.user,
            entry.action,
            entry.detail
        ].forEach(value => {

            const cell = document.createElement("td");

            cell.textContent = value === undefined ? "" : value;

            row.appendChild(cell);
        });

        auditTable.appendChild(row);
    });
}

displayAuditLog();
