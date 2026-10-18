import SwiftUI

/// A screen's title and its optional one-line purpose.
///
/// **Decision basis:** `MACGUARD_DESIGN_SYSTEM.md` Part 4.E / `_PHASE3_COMPONENT_SPECS.md` §B.4.
/// Base: `ShellScreenTitle` (`ProductShell.swift:293-311`).
///
/// **Load-bearing accessibility requirement, baked in rather than optional:**
/// `.accessibilityAddTraits(.isHeader)` is applied here unconditionally — not left for a call
/// site to remember. This is, per the design system doc, "the single most load-bearing
/// accessibility lesson from the real archaeology": `.isHeader` is applied at 20 real sites
/// app-wide, and the real component's own code comment records a genuine historical defect this
/// guards against — the pre-"Cut 2" Authentication panels shipped without heading traits, which
/// is why rotor/heading navigation skipped most of that screen (`ProductShell.swift:291-292`).
///
/// **Forbidden variant:** a title `Text` with no `.isHeader` is not `MGScreenHeader` — if a
/// screen needs styled-but-non-heading text, use plain `Text` instead of reaching for this type
/// and skipping its accessibility contract.
public struct MGScreenHeader: View {
    private let title: String
    private let summary: String?

    /// - Parameters:
    ///   - title: the screen's title. Always rendered with `.isHeader` — see the type's doc
    ///     comment for why this is not optional.
    ///   - summary: an optional one-line purpose statement, rendered below the title.
    public init(title: String, summary: String? = nil) {
        self.title = title
        self.summary = summary
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: MGSpacing.xs) {
            Text(title)
                .font(MGTypography.screenTitle)
                .bold()
                .accessibilityAddTraits(.isHeader)
            if let summary {
                Text(summary)
                    .font(MGTypography.body)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// A titled group of rows.
///
/// **Decision basis:** same citation as `MGScreenHeader`. Base: `ShellSection`
/// (`ProductShell.swift:314-334`).
///
/// **Same load-bearing accessibility requirement as `MGScreenHeader`:** `.isHeader` is baked into
/// this component's own body, unconditionally, for the same reason — see `MGScreenHeader`'s doc
/// comment. A screen that needs a styled-but-non-heading label is not this component either.
public struct MGSectionHeader<Content: View>: View {
    private let title: String
    private let subtitle: String?
    @ViewBuilder private let content: () -> Content

    /// - Parameters:
    ///   - title: the section's title. Always rendered with `.isHeader`.
    ///   - subtitle: an optional secondary line, rendered below the title.
    ///   - content: the section's rows.
    public init(
        title: String,
        subtitle: String? = nil,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.title = title
        self.subtitle = subtitle
        self.content = content
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: MGSpacing.sm) {
            Text(title)
                .font(MGTypography.sectionTitle)
                .accessibilityAddTraits(.isHeader)
            if let subtitle {
                Text(subtitle)
                    .font(MGTypography.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
