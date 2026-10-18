import SwiftUI

/// The data needed to present one gated confirmation — title, consequence message, and the
/// confirm/cancel button titles.
///
/// **Decision basis:** `MACGUARD_DESIGN_SYSTEM.md` Part 4.M / `_PHASE3_COMPONENT_SPECS.md` §B.13.
/// Closes a confirmed real defect: the exact same posture-switch confirmation dialog was
/// independently, byte-for-byte-identically declared three times in MacUSBGuard
/// (`HomeScreen.swift:91-107`, `USBGuardScreen.swift:510-526`, and a dead copy at
/// `MainView.swift:3390-3400+`). This type makes the shape definable once.
///
/// **Accessibility requirement, carried forward from the spec:** every real gated site paired
/// the dialog's title with a `message:` naming the consequence — both `title` and `message` are
/// therefore required (non-optional), not just a title.
public struct MGConfirmationDialog {
    public let title: String
    public let message: String
    public let confirmTitle: String
    public let cancelTitle: String
    public let isDestructive: Bool

    /// - Parameters:
    ///   - title: the dialog's title.
    ///   - message: the consequence of confirming, stated in plain language. Required — not
    ///     optional — because every real gated site in the archaeology paired a title with a
    ///     message naming the consequence.
    ///   - confirmTitle: label for the confirm action.
    ///   - cancelTitle: label for the cancel action. Defaults to "Cancel".
    ///   - isDestructive: whether the confirm button should be styled `.destructive`. Defaults
    ///     to `true`. Note: when this dialog is presented via `MGDestructiveButton`, the confirm
    ///     button is *always* rendered with `role: .destructive` regardless of this value — see
    ///     `MGDestructiveButton`'s doc comment for why that is a deliberate, non-overridable
    ///     guarantee rather than a bug.
    public init(
        title: String,
        message: String,
        confirmTitle: String,
        cancelTitle: String = "Cancel",
        isDestructive: Bool = true
    ) {
        self.title = title
        self.message = message
        self.confirmTitle = confirmTitle
        self.cancelTitle = cancelTitle
        self.isDestructive = isDestructive
    }
}

public extension View {
    /// Attaches an `MGConfirmationDialog`'s content as a native `.confirmationDialog`.
    ///
    /// The confirm button's `role: .destructive` is applied here, from the dialog's own
    /// `isDestructive` flag — **never** left to the call site to remember, which is exactly the
    /// real defect this type closes (`MacProtectionScreen.swift:468-470`: gated, but the confirm
    /// button carried no `role:` at all).
    func mgConfirmationDialog(
        _ dialog: MGConfirmationDialog,
        isPresented: Binding<Bool>,
        onConfirm: @escaping () -> Void
    ) -> some View {
        confirmationDialog(dialog.title, isPresented: isPresented, titleVisibility: .visible) {
            Button(dialog.confirmTitle, role: dialog.isDestructive ? .destructive : nil) {
                onConfirm()
            }
            Button(dialog.cancelTitle, role: .cancel) {}
        } message: {
            Text(dialog.message)
        }
    }
}
