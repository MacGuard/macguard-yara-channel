import SwiftUI

/// Typography tokens shared across every MacGuard product.
///
/// **Decision basis:** `MACGUARD_DESIGN_SYSTEM.md` Part 1 / `_PHASE2_TOKEN_DECISIONS.md` §1.
/// MacUSBGuard's prior named-token attempt (`DesignTokens.Typography`) got 0% real adoption
/// across all 20 audited files — including the one screen it was built for. `MGTypography` is
/// therefore deliberately **thin, enforced aliases over the system semantic styles already in
/// dominant real use**: adopting the token costs nothing visually, and a lint rule can
/// mechanically flag any remaining raw `.font(...)` call.
///
/// Because every token except `.metric` wraps a `Font.TextStyle` rather than a fixed point size,
/// Dynamic Type scaling is inherited for free. `.metric` is the one exception — see its doc
/// comment below for the accessibility caveat carried forward from the design system doc.
public enum MGTypography {

    /// Rare, large display text. 2 real uses app-wide (onboarding icon, welcome screen).
    public static var hero: Font { .largeTitle }

    /// Screen-level title (`ShellScreenTitle`'s title).
    public static var screenTitle: Font { .title2 }

    /// Section-level title. 56 real occurrences.
    public static var sectionTitle: Font { .headline }

    /// Card title. Same value as `.sectionTitle` — two names, one value, deliberately: no
    /// separate card-title size exists anywhere in the real app, so none is invented here.
    public static var cardTitle: Font { .headline }

    /// Primary row body text. 77 real occurrences, the dominant primary-row body size.
    public static var body: Font { .callout }

    /// Secondary body text. 211-215 real occurrences — the single most common text style in
    /// the app, doing double duty as both "secondary" and plain "default" in practice.
    public static var bodySecondary: Font { .subheadline }

    /// Fine print / metadata captions. 133 real occurrences.
    public static var caption: Font { .caption }

    /// Chip / status fine-print tier. 22 real occurrences.
    public static var status: Font { .caption2 }

    /// Large numeral display (e.g. a security posture score).
    ///
    /// **Corrected basis** (see `MACGUARD_DESIGN_SYSTEM.md` Part 1, correction log #3): this was
    /// previously, incorrectly, cited against 28pt SF Symbol icon sizes inside empty-state
    /// placeholders. The real, re-verified basis is the security posture score,
    /// `ProductShell.swift:793-797`:
    /// `Text(String(format: "%.1f", score.value)).font(.title).fontWeight(.bold).monospacedDigit()`.
    ///
    /// **Accessibility caveat, carried forward verbatim from the design system doc:**
    /// `monospacedDigit()` fixes glyph *width*, not point size — a fixed-weight bold `.title`
    /// numeral can still overflow its container at the largest accessibility text sizes. Any
    /// consumer building a metric display on top of this token needs an explicit Dynamic Type
    /// overflow audit before shipping; this package does not claim that audit has been done.
    public static var metric: Font { .title.bold().monospacedDigit() }

    /// Monospaced technical text: timestamps, bus addresses, identifiers, fingerprints.
    /// Exactly `DesignTokens.Typography.technicalMono`'s declared (but never-called) definition —
    /// `.caption` is the base because it was the most frequent of the three hand-rolled bases
    /// (`.callout`/`.caption`/`.caption2`) found at the ~20 real sites this token replaces.
    public static var code: Font { .system(.caption, design: .monospaced) }

    /// Alias for `.code` — some call sites read more naturally as "identifier" than "code".
    /// Intentionally the same value; see `.cardTitle`/`.sectionTitle` for the same naming
    /// philosophy (two names, one value, when no second real size exists).
    public static var identifier: Font { .system(.caption, design: .monospaced) }
}
