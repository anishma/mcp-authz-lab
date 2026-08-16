// Exercise 3 instructor solution: fine-grained, least-privilege policies.
// Cedar denies anything not explicitly permitted.

// Everyone may list invoices.
permit (
  principal,
  action == Action::"invoke",
  resource == Tool::"list_invoices"
);

// Payments: only up to the caller's own payment limit.
permit (
  principal,
  action == Action::"invoke",
  resource == Tool::"pay_invoice"
) when {
  context.args.amount <= principal.payment_limit
};

// HR records: your own record, or you work in HR.
permit (
  principal,
  action == Action::"invoke",
  resource == Tool::"get_employee"
) when {
  context.args.employee_id == principal.employee_id ||
  principal.department == "hr"
};

// Email: internal recipients only.
permit (
  principal,
  action == Action::"invoke",
  resource == Tool::"send_email"
) when {
  context.args.to like "*@payflow.example"
};
