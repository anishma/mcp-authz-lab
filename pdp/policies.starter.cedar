// Exercise 3 starter policy set.
//
// The PDP evaluates every tool invocation as this Cedar request:
//   principal = User::"<sub claim from the caller's JWT>"
//   action    = Action::"invoke"
//   resource  = Tool::"<MCP tool name>"
//   context   = { "args": { ...the tool-call arguments... } }
//
// Principal attributes available (loaded from entities.json):
//   principal.department      e.g. "finance"
//   principal.employee_id     e.g. "E001"
//   principal.payment_limit   e.g. 500
//
// Right now NOTHING is permitted (Cedar denies by default).
// Your task: write the narrowest policies that let each user do their job.
// The instructor solution is in policies.solution.cedar — try it yourself first.

// 1. Everyone may list invoices.
permit (
  principal,
  action == Action::"invoke",
  resource == Tool::"list_invoices"
);

// 2. TODO: permit pay_invoice, but only up to the caller's payment_limit.
//    Hint: when { context.args.amount <= principal.payment_limit }

// 3. TODO: permit get_employee, but only for the caller's own record,
//    unless the caller works in HR.

// 4. TODO: permit send_email, but only to company addresses.
//    Hint: when { context.args.to like "*@payflow.example" }
