import AppKit
import SwiftUI

/// WCAG-contrast-corrected verdict colors, shared across every MacGuard product.
///
/// **This is a faithful port, not a reimplementation.** The blend-toward-black/white-in-5%-steps
/// algorithm, the WCAG relative-luminance/contrast math, and the 4.5:1 floor are copied verbatim
/// (modulo renaming to avoid colliding with MacUSBGuard's own internal `SecurityTint`) from:
///
///     Sources/MacUSBGuardApp/SecurityTint.swift
///     (MacUSBGuard repo, read in full before porting — see MACGUARD_DESIGN_SYSTEM.md §3.1)
///
/// This is deliberately the single most safety-critical piece of this package: a security
/// product's status colors must stay legible, by *measurement*, not by eye — approximating this
/// with four fixed `Color` literals would silently drop that guarantee for every future consuming
/// screen. Do not replace the algorithm below with fixed colors.
///
/// **Original doc comment, preserved for context (measured BEFORE the fix, against
/// `.windowBackgroundColor`, floor 4.5:1):**
///
///     light    green 1.80:1   orange 1.86:1   red 3.00:1   blue 3.40:1
///     dark     green 7.15:1   orange 6.24:1   red 3.76:1   blue 3.52:1
///
/// Those are correct values for what those colors are *for* (glyph fills, selection, tint) and
/// far below the 4.5:1 WCAG 2.2 AA floor for text under 18pt — which is every real use of these.
///
/// **What this does not do** (carried forward from the original): it does not claim conformance.
/// The measurement is against the opaque window background; a color composited over a
/// translucent material can differ, and this cannot see that. It is a floor, enforced. Color is
/// never the only signal regardless — every state that uses a tint is also meant to be drawn
/// with an SF Symbol and a written word (see `MGStatusBadge`'s non-optional `text:` parameter,
/// which exists for exactly this reason).
public enum MGSecurityTint {

    /// WCAG 2.2 AA floor for text below 18pt, which is every use of these tokens.
    public static let floor: Double = 4.5

    /// Enforcing, with evidence.
    public static let protected: Color = accessible(.systemGreen)
    /// Something the reader can act on.
    public static let attention: Color = accessible(.systemOrange)
    /// A refusal or a fault.
    public static let failure: Color = accessible(.systemRed)
    /// Reported by macOS rather than enforced directly by the product.
    public static let reported: Color = accessible(.systemBlue)

    /// The adjusted color for a system color, as a SwiftUI `Color`.
    public static func accessible(_ base: NSColor) -> Color {
        Color(nsColor: accessibleNSColor(base))
    }

    /// Exposed as `NSColor` so a contrast test can measure exactly what ships rather than
    /// re-deriving it and measuring its own arithmetic.
    public static func accessibleNSColor(_ base: NSColor) -> NSColor {
        NSColor(name: nil) { appearance in
            var resolved = base
            appearance.performAsCurrentDrawingAppearance {
                resolved = adjusted(base, background: .windowBackgroundColor,
                                     darkening: !isDark(appearance))
            }
            return resolved
        }
    }

    // MARK: - The arithmetic (ported verbatim from SecurityTint.swift:64-102)

    private static func isDark(_ appearance: NSAppearance) -> Bool {
        appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
    }

    /// Blends `base` toward black or white until it clears the floor.
    ///
    /// Small steps and a bounded loop: 20 steps of 5% cannot run away, and returning the last
    /// step when none clears is the honest failure — a color that cannot reach the floor should
    /// be as close as it can get, not silently replaced by the label color, which would lose the
    /// state.
    private static func adjusted(_ base: NSColor, background: NSColor,
                                  darkening: Bool) -> NSColor {
        let target: NSColor = darkening ? .black : .white
        var candidate = base
        for step in 0...20 {
            candidate = base.blended(withFraction: CGFloat(step) * 0.05, of: target) ?? base
            if contrast(candidate, background) >= floor { return candidate }
        }
        return candidate
    }

    /// WCAG relative luminance and contrast — the same arithmetic a contrast test would use.
    private static func luminance(_ colour: NSColor) -> Double {
        guard let srgb = colour.usingColorSpace(.sRGB) else { return 0 }
        func channel(_ value: CGFloat) -> Double {
            let v = Double(value)
            return v <= 0.04045 ? v / 12.92 : pow((v + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * channel(srgb.redComponent)
            + 0.7152 * channel(srgb.greenComponent)
            + 0.0722 * channel(srgb.blueComponent)
    }

    private static func contrast(_ a: NSColor, _ b: NSColor) -> Double {
        let x = luminance(a), y = luminance(b)
        return (max(x, y) + 0.05) / (min(x, y) + 0.05)
    }
}

extension ShapeStyle where Self == Color {
    /// Shorthands, so a call site reads as the state it means rather than as a color.
    /// `.foregroundStyle(.protected)` says what the row is; `.green` only says what it looks like.
    public static var mgProtected: Color { MGSecurityTint.protected }
    public static var mgAttention: Color { MGSecurityTint.attention }
    public static var mgFailure: Color { MGSecurityTint.failure }
    public static var mgReported: Color { MGSecurityTint.reported }
}
