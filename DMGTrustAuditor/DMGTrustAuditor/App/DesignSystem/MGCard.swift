import SwiftUI

/// Fixed-shape card container, replacing `ShellCard`/`ModernCard`.
///
/// **Decision basis:** `MACGUARD_DESIGN_SYSTEM.md` Part 4.G / `_PHASE3_COMPONENT_SPECS.md`.
/// `ShellCard` (`ProductShell.swift:337-353`) is `VStack(spacing: Spacing.sm)` +
/// `.padding(Spacing.md)` + `RoundedRectangle(cornerRadius: Radius.card)` filled with
/// `Surface.panel`, 1pt `Surface.borderHairline` stroke overlay. `ModernCard`
/// (`DesignTokens.swift:127-153`) is structurally identical with padding/cornerRadius
/// *parameterized* — defaulting to exactly `ShellCard`'s values, so the two render
/// byte-identical output at their defaults.
///
/// **Decision:** build on `ShellCard`'s FIXED shape, not `ModernCard`'s parameterized one — this
/// type intentionally does not expose `padding`/`cornerRadius` parameters. `Radius.card` is 10pt
/// (confirmed real value, `DesignTokens.swift:40`).
/// Matches `DesignTokens.Radius.card` exactly (confirmed real value, `DesignTokens.swift:40`,
/// "Primary cards, charts, inspectors"). This package does not yet expose a general `MGRadius`
/// token namespace (not in this version's scope — see the package README) so the value is
/// named here, at file scope, rather than left as a bare literal inside `MGCardBase`.
private let mgCardRadius: CGFloat = 10

struct MGCardBase<Content: View>: View {
    let accentTint: Color?
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: MGSpacing.sm, content: content)
            .padding(MGSpacing.md)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: mgCardRadius)
                    .fill(MGColor.Surface.panel)
                    .overlay(
                        RoundedRectangle(cornerRadius: mgCardRadius)
                            .strokeBorder(accentTint ?? MGColor.Surface.borderHairline, lineWidth: 1)
                    )
            )
    }
}

/// Neutral information card. Accent variant keyed to `MGHealthStatus.neutral` per
/// `MACGUARD_DESIGN_SYSTEM.md` Part 4.G.
public struct MGInfoCard<Content: View>: View {
    @ViewBuilder private let content: () -> Content

    public init(@ViewBuilder content: @escaping () -> Content) {
        self.content = content
    }

    public var body: some View {
        MGCardBase(accentTint: nil, content: content)
    }
}

/// Warning-accented card. Accent variant keyed to `MGHealthStatus.attention` per
/// `MACGUARD_DESIGN_SYSTEM.md` Part 4.G.
public struct MGWarningCard<Content: View>: View {
    @ViewBuilder private let content: () -> Content

    public init(@ViewBuilder content: @escaping () -> Content) {
        self.content = content
    }

    public var body: some View {
        MGCardBase(accentTint: MGHealthStatus.degraded.tint, content: content)
    }
}

/// Critical-accented card. Accent variant keyed to `MGHealthStatus.failed` per
/// `MACGUARD_DESIGN_SYSTEM.md` Part 4.G.
public struct MGCriticalCard<Content: View>: View {
    @ViewBuilder private let content: () -> Content

    public init(@ViewBuilder content: @escaping () -> Content) {
        self.content = content
    }

    public var body: some View {
        MGCardBase(accentTint: MGHealthStatus.failed.tint, content: content)
    }
}
