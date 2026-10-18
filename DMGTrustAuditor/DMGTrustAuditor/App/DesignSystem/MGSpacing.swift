import CoreGraphics

/// Spacing tokens shared across every MacGuard product.
///
/// **Decision basis:** `MACGUARD_DESIGN_SYSTEM.md` Part 2 / `_PHASE2_TOKEN_DECISIONS.md` §2.
/// Keeps the existing `DesignTokens.Spacing` scale unchanged and adds exactly one promoted
/// tier (`xxxs`). High-repetition *undeclared* values (6, 10, 14, 18, ...) are documented in
/// the design system doc as DRIFT needing case-by-case visual QA — they are deliberately
/// **not** promoted to tokens here; repetition of a mistake is not evidence of an intentional
/// scale.
public enum MGSpacing {
    /// 1pt — promoted from 18 raw occurrences; sits cleanly below `xxs`.
    public static let xxxs: CGFloat = 1
    /// 2pt — micro separation (badge padding, icon-to-label tight).
    public static let xxs: CGFloat = 2
    /// 4pt — tight element spacing.
    public static let xs: CGFloat = 4
    /// 8pt — standard internal spacing.
    public static let sm: CGFloat = 8
    /// 12pt — component spacing.
    public static let md: CGFloat = 12
    /// 16pt — section content spacing.
    public static let lg: CGFloat = 16
    /// 20pt — inter-card spacing.
    public static let xl: CGFloat = 20
    /// 28pt — major section separation. Highest declared tier; no `xxxl` added this round.
    public static let xxl: CGFloat = 28
}
