import SwiftUI
import AppKit

/// Surface tokens shared across every MacGuard product.
///
/// **Decision basis:** `MACGUARD_DESIGN_SYSTEM.md` Part 3.3-3.4 / `_PHASE2_TOKEN_DECISIONS.md`
/// §3. Ports `DesignTokens.Surface` (`DesignTokens.swift:48-78` in the MacUSBGuard app) verbatim
/// — all of `canvas`/`panel`/`subtle`/`elevated`/`borderHairline`/`borderActive` were found
/// CANONICAL by the archaeology (consistent real adoption), plus one new token
/// (`overlaySelected`) promoted this round from a consistently-recurring opacity value.
public enum MGColor {

    /// Namespace for layered background/foreground surface fills.
    public enum Surface {
        /// Canvas background for window content. Real system semantic color, not a flat hue —
        /// tracks light/dark mode automatically.
        public static var canvas: Color {
            Color(nsColor: .windowBackgroundColor)
        }

        /// Subordinate panel background (cards, detail panes).
        public static var panel: Color {
            Color(nsColor: .controlBackgroundColor)
        }

        /// Subtle grouping fill — replaces heavy borders. Opacity 0.06, exact decided value.
        public static var subtle: Color {
            Color.secondary.opacity(0.06)
        }

        /// Elevated interactive fill (hover states). Opacity 0.12, exact decided value.
        public static var elevated: Color {
            Color.secondary.opacity(0.12)
        }

        /// Crisp hairline divider / outline border. Opacity 0.14, exact decided value.
        public static var borderHairline: Color {
            Color.secondary.opacity(0.14)
        }

        /// Active selection border. Opacity 0.45 of the accent color, exact decided value.
        public static var borderActive: Color {
            Color.accentColor.opacity(0.45)
        }

        /// Selected-state fill for chips/pane-options.
        ///
        /// **New token** (`MACGUARD_DESIGN_SYSTEM.md` Part 3.4): opacity 0.18 recurs 6 times,
        /// consistently, as a de-facto "this chip/pane-option is selected" fill
        /// (`ModernStatusChip`'s selected state, pane-selector selection) — one consistent
        /// meaning everywhere it appears, which is exactly what earns it a token (unlike the
        /// opacity-drift values documented as NOT promoted in the design system doc §3.5-3.6:
        /// 0.4/0.3/0.08/0.5/0.35/0.1/0.07, and the still-open 0.15 "capsule fill" candidate,
        /// which is explicitly flagged for a *future* token-review pass, not resolved here).
        public static var overlaySelected: Color {
            Color.accentColor.opacity(0.18)
        }
    }
}
