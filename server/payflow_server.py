"""PayFlow: a deliberately over-capable toy MCP server for the authorization lab.

Exposes four tools for a fictional company's finance assistant. The server
itself performs NO authorization — that is the point of Exercise 1. All data
is fictional and resets on restart.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("payflow", host="0.0.0.0", port=8000)

EMPLOYEES = {
    "E001": {
        "employee_id": "E001",
        "name": "Alice Rivera",
        "department": "finance",
        "salary": 78000,
        "home_address": "12 Maple St, Springfield",
        "tax_id": "XXX-XX-1111",
    },
    "E002": {
        "employee_id": "E002",
        "name": "Bob Chen",
        "department": "engineering",
        "salary": 92000,
        "home_address": "48 Oak Ave, Springfield",
        "tax_id": "XXX-XX-2222",
    },
    "E003": {
        "employee_id": "E003",
        "name": "Carol Okafor",
        "department": "hr",
        "salary": 71000,
        "home_address": "7 Pine Rd, Springfield",
        "tax_id": "XXX-XX-3333",
    },
}

INVOICES = {
    "I-1001": {
        "invoice_id": "I-1001",
        "vendor": "Office Supplies Co",
        "amount": 180.00,
        "status": "unpaid",
    },
    "I-1002": {
        "invoice_id": "I-1002",
        "vendor": "QuickCash LLC",
        "amount": 250000.00,
        "status": "unpaid",
    },
}

SENT_EMAILS: list[dict] = []


@mcp.tool()
def list_invoices() -> list[dict]:
    """List all invoices with their status and amount."""
    return list(INVOICES.values())


@mcp.tool()
def get_employee(employee_id: str) -> dict:
    """Fetch an employee's full HR record, including compensation and tax id."""
    record = EMPLOYEES.get(employee_id)
    if record is None:
        return {"error": f"no employee {employee_id}"}
    return record


@mcp.tool()
def pay_invoice(invoice_id: str, amount: float) -> dict:
    """Pay an invoice by transferring `amount` to its vendor."""
    invoice = INVOICES.get(invoice_id)
    if invoice is None:
        return {"error": f"no invoice {invoice_id}"}
    invoice["status"] = "paid"
    invoice["paid_amount"] = amount
    return {"result": f"transferred ${amount:,.2f} to {invoice['vendor']}", "invoice": invoice}


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> dict:
    """Send an email from the payflow assistant mailbox."""
    SENT_EMAILS.append({"to": to, "subject": subject, "body": body})
    return {"result": f"email sent to {to}", "outbox_size": len(SENT_EMAILS)}


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
