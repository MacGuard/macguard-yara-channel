import SwiftUI

/// The reconciled, 9-case status vocabulary shared across every MacGuard product.
///
/// **Decision basis:** `MACGUARD_DESIGN_SYSTEM.md` Part 4.A / `_PHASE3_COMPONENT_SPECS.md` §A.2.
/// Reconciles three independently-declared real status→(color,icon) switches found in
/// MacUSBGuard (`SecurityStatusKind`, `DomainCard.statusColour`/`.statusSymbol`,
/// `PostureRow.color` + `PostureState.symbolName`) that agreed on some cases and disagreed on
/// others. Every case below is a real case found in at least one of the three switches; nothing
/// is invented to fill the table. Candidate states with zero real occurrence (`TRUSTED`,
/// `REVIEW`, `QUARANTINED`, `DENIED`, `VERIFIED`, `UNVERIFIED`, a generic top-level `AVAILABLE`,
/// `HEALTHY`, `ERROR`) are deliberately omitted.
///
/// **Forbidden:** no silent sixth tint. Any new case must be reviewed against the design system
/// doc's table, not added ad hoc by a consuming screen — that is exactly how `DomainCard` and
/// `PostureRow` ended up with two more divergent switches in the first place.
public enum MGHealthStatus: CaseIterable {
    /// Confirmed enforcing, with evidence.
    case protected
    /// macOS reports/handles this; the product does not enforce it directly.
    case reportedByOS
    /// Running, not blocking anything.
    case observing
    /// Enforcing, with reduced/unverified coverage.
    case degraded
    /// A refusal, or an operation that did not do what was asked.
    case failed
    /// Off, and not by a fault — a settled, unremarkable fact.
    case disabled
    /// This Mac's hardware/OS cannot do this.
    case notSupported
    /// Nobody has read this yet — not a claim either way.
    case unknown
    /// A settled fact with no verdict attached.
    case neutral

    /// Canonical SF Symbol per `MACGUARD_DESIGN_SYSTEM.md` Part 5's "Resolution against
    /// MGHealthStatus" table.
    public var symbolName: String {
        switch self {
        case .protected: return "checkmark.shield.fill"
        case .reportedByOS: return "shield.lefthalf.filled"
        case .observing: return "eye"
        case .degraded: return "exclamationmark.shield.fill"
        case .failed: return "xmark.octagon.fill"
        case .disabled: return "shield.slash"
        case .notSupported: return "minus.circle"
        case .unknown: return "questionmark.circle.fill"
        case .neutral: return "circle"
        }
    }

    /// Canonical tint per the design system doc's reconciled table.
    public var tint: Color {
        switch self {
        case .protected: return MGSecurityTint.protected
        case .reportedByOS: return MGSecurityTint.reported
        case .observing: return MGSecurityTint.attention
        case .degraded: return MGSecurityTint.attention
        case .failed: return MGSecurityTint.failure
        case .disabled:
            // NOTE (verbatim from _PHASE3_COMPONENT_SPECS.md §A.2 / MACGUARD_DESIGN_SYSTEM.md
            // Part 4.A, "OPEN — NEEDS HUMAN SIGN-OFF"):
            //
            // "PostureRow(.disabled) maps to .degraded/amber while DomainCard(.disabled) maps to
            // plain .secondary/gray. These are not obviously the same real-world situation: a
            // hardware feature being off (PostureState.disabled) is something the reader may want
            // to act on; a domain's enforcement being off (DomainCard's .disabled enforcement
            // case) is described in its own comment as neutral, 'like the posture rows' UNKNOWN:
            // nobody has read it' — a rationale that actually describes .unknown, misapplied in
            // place to .disabled too. The table above resolves this by treating feature-off and
            // enforcement-off as two different real states, but this is a product decision, not
            // a design-system decision — ask Core/product before shipping MGStatusBadge on top
            // of it, per the brief's own §35 OVERRIDE process. Do not silently pick one tint and
            // call it closed."
            //
            // This implementation ships the ONE value the reconciled table in
            // MACGUARD_DESIGN_SYSTEM.md Part 4.A actually assigned to `.disabled`: DomainCard's
            // neutral/secondary interpretation. The PostureRow(.disabled)->amber reading is NOT
            // implemented here and remains an open product question — do not resolve it by
            // editing this case without the human sign-off the doc calls for.
            return Color.secondary
        case .notSupported: return Color.secondary
        case .unknown: return Color.secondary
        case .neutral: return Color.secondary
        }
    }

    /// True only for `.protected` — ported verbatim from `SecurityStatusKind.permitsSuccessStyling`,
    /// the one piece of the existing mechanism the design system doc says must not be lost.
    public var permitsSuccessStyling: Bool {
        self == .protected
    }
}
