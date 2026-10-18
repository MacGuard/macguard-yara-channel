import SwiftUI

/// Primary action button. Generalizes the real `.buttonStyle(.borderedProminent)` convention
/// seen throughout MacUSBGuard (`ShellProtectionSummary`, `ProductShell.swift:570-606`) — no new
/// behavior, a named wrapper so the choice is explicit rather than picked per call site.
///
/// **Decision basis:** `MACGUARD_DESIGN_SYSTEM.md` Part 4.H / `_PHASE3_COMPONENT_SPECS.md` §B.8.
public struct MGPrimaryButton: View {
    private let title: String
    private let action: () -> Void

    public init(_ title: String, action: @escaping () -> Void) {
        self.title = title
        self.action = action
    }

    public var body: some View {
        Button(title, action: action)
            .buttonStyle(.borderedProminent)
    }
}

/// Secondary action button. Generalizes the real `.buttonStyle(.bordered)` convention.
///
/// Also the documented escape hatch for "fire immediately, no confirmation": a call site that
/// genuinely wants that behavior uses `MGSecondaryButton`, a legible, reviewable statement of
/// intent — never `MGDestructiveButton` with a bypassed confirmation, which this API makes
/// impossible to construct in the first place.
public struct MGSecondaryButton: View {
    private let title: String
    private let action: () -> Void

    public init(_ title: String, action: @escaping () -> Void) {
        self.title = title
        self.action = action
    }

    public var body: some View {
        Button(title, action: action)
            .buttonStyle(.bordered)
    }
}

/// A destructive action button that cannot be constructed without a confirmation.
///
/// **The two real defects this closes** (`MACGUARD_DESIGN_SYSTEM.md` Part 4.H /
/// `_PHASE3_COMPONENT_SPECS.md` §B.8), both confirmed by direct re-read of MacUSBGuard:
///
/// 1. `ApprovalViews.swift:270-272` — a `role: .destructive` button with **no** enclosing
///    `.confirmationDialog`/`.alert` anywhere in the view. Fires immediately on tap.
/// 2. `MacProtectionScreen.swift:468-470` — inside a `.confirmationDialog` that **is** gated, the
///    confirm button carries **no `role:` parameter at all**; only its Cancel sibling is styled
///    `.cancel`. Gated but unstyled.
///
/// **Why the API below makes both mistakes structurally impossible:**
/// - `confirmation:` is a **non-optional** `MGConfirmationDialog` — there is no initializer that
///   skips it, so there is no code path that produces an unconfirmed destructive button (closes
///   defect #1). A call site that genuinely wants "fire immediately" must use a plain
///   `MGSecondaryButton` instead — a legible, reviewable statement of intent, not a silent
///   omission.
/// - The confirmation's confirm button is rendered with `role: .destructive` **unconditionally**
///   by this type's own `body` — not by reading `confirmation.isDestructive` (which exists for
///   standalone uses of `MGConfirmationDialog` outside this button), and never by the call site
///   remembering to add a role (closes defect #2).
public struct MGDestructiveButton: View {
    private let title: String
    private let confirmation: MGConfirmationDialog
    private let perform: () -> Void

    @State private var isPresented = false

    /// - Parameters:
    ///   - title: label for the destructive trigger button itself.
    ///   - confirmation: the dialog content to present before `perform` runs. Non-optional by
    ///     design — see the type's doc comment.
    ///   - perform: the destructive action, invoked only after the user confirms.
    public init(title: String, confirmation: MGConfirmationDialog, perform: @escaping () -> Void) {
        self.title = title
        self.confirmation = confirmation
        self.perform = perform
    }

    public var body: some View {
        Button(title, role: .destructive) {
            isPresented = true
        }
        .confirmationDialog(confirmation.title, isPresented: $isPresented, titleVisibility: .visible) {
            // Role is ALWAYS .destructive here, unconditionally — never left to the call site,
            // and never read from a flag a call site could flip. This is the one line closing
            // MacProtectionScreen.swift:468-470's defect.
            Button(confirmation.confirmTitle, role: .destructive) {
                perform()
            }
            Button(confirmation.cancelTitle, role: .cancel) {}
        } message: {
            Text(confirmation.message)
        }
    }
}
