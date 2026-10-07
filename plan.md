# SplitVault — Drips Wave Program Issue Plan

The Drips Wave Program accelerates open-source development on Stellar by matching maintainers with contributors through well-scoped, actionable issues during sprint cycles. This plan outlines the issue taxonomy and task breakdown for **SplitVault** sprint releases.

---

## 🎯 Issue Categories & Work Items

### 1. 🐛 Bug Fixes & Safety Hardening
* **Boundary Math Checks:** Resolve potential arithmetic overflows/underflows in fee tiering and proportional payout calculations.
* **State Transition Safety:** Prevent re-entrancy risks, invalid state mutations on cancelled or archived invoices, and unauthorized caller access.
* **Storage Lease Expiry:** Hard-check TTL extensions and rent balance handling for persistent invoice data.

### 2. ⚡ Feature Additions & Extensions
* **Installment & Milestone Payouts:** Add multi-stage releasing for milestone-based project splitting.
* **Multi-Token Basket Escrow:** Extend invoice options to support secondary stablecoins or custom Stellar asset pairs.
* **Tiered Fee Waivers & Delegation:** Implement role-based fee exemptions for registered DAO/treasury accounts.
* **Batch Invoice Operations:** Enable bulk payment processing and single-transaction multi-invoice funding.

### 3. 🧪 Testing & Quality Assurance
* **Fuzz & Property Testing:** Expand target harnesses in `fuzz/` to cover arbitrary payment ratios, sequence permutations, and zero-amount edge cases.
* **Integration Lifecycle Suites:** Implement comprehensive multi-payer lifecycle scenarios with simulated ledger progression.
* **Storage Key Collisions:** Maintain baseline verification (`storage_snapshot`) to ensure XDR key uniqueness.

### 4. 📚 Documentation & Developer Experience
* **Client Integration Guides:** Provide TypeScript & Rust code snippets for frontend integration with `soroban-client`.
* **API Documentation:** Keep `docs/API.md` synchronized with contract method signatures and event schemas.
* **Architecture Diagrams:** Maintain sequence diagrams illustrating invoice states, escrow locks, and refund flows.

### 5. 🚀 Gas & Compute Budget Optimization
* **Storage Key Packing:** Optimize contract state representations to minimize XDR serialization overhead.
* **WASM Binary Size Reduction:** Benchmark and reduce compiled size using Soroban opt flags.
* **Instruction Budget Auditing:** Audit and optimize compute unit consumption during large multi-recipient releases.

---

## 📋 Issue Scoping & Contributor Workflow

1. **Clear Acceptance Criteria:** Every issue must define input/output specs and expected unit test coverage.
2. **Complexity Labels:** Categorized as `good first issue` (docs/simple tests), `medium` (feature additions), or `high` (contract core logic/security).
3. **Review & Merge Checklist:** PRs require passing `cargo test --workspace` and updated storage key snapshots.
