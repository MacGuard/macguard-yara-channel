import SwiftUI

/// A read-only status badge: icon + tint + plain-language text.
///
/// **Decision basis:** `MACGUARD_DESIGN_SYSTEM.md` Part 4.A / `_PHASE3_COMPONENT_SPECS.md` §A.3.
/// 1:1 generalization of `ShellStatusLabel` (`ProductShell.swift:378-395`).
///
/// **Load-bearing structural requirement:** `text:` is a non-optional `String`, not `String?`.
/// This makes a color-only badge structurally impossible to construct (WCAG 1.4.1 — color is
/// never the only signal). Every real site the archaeology found pairs tint with an SF Symbol
/// *and* a written word; this type enforces that at the API boundary rather than by convention.
public struct MGStatusBadge: View {
    private let status: MGHealthStatus
    private let text: String
    private let bold: Bool

    /// - Parameters:
    ///   - status: the reconciled health state this badge represents.
    ///   - text: the plain-language label. Non-optional by design — see the type's doc comment.
    ///   - bold: matches `ShellStatusLabel`'s real `.headline`/`.callout` size switch exactly.
    public init(status: MGHealthStatus, text: String, bold: Bool = false) {
        self.status = status
        self.text = text
        self.bold = bold
    }

    public var body: some View {
        Label {
            Text(text)
                .font(bold ? MGTypography.sectionTitle : MGTypography.body)
        } icon: {
            Image(systemName: status.symbolName)
        }
        .foregroundStyle(status.tint)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(text)
    }
}
