import Foundation

/// One source of truth for the UI language so views and model messages agree.
/// Defaults to the system language; the in-app picker persists an override.
enum AppLanguage {
    static let key = "appLanguageSpanish"
    static var isSpanish: Bool {
        if let stored = UserDefaults.standard.object(forKey: key) as? Bool { return stored }
        return Locale.preferredLanguages.first?.hasPrefix("es") ?? false
    }
    static func set(spanish: Bool) { UserDefaults.standard.set(spanish, forKey: key) }
    static func tr(_ es: String, _ en: String) -> String { isSpanish ? es : en }
    /// A plain-language sentence followed by the technical detail, kept apart so the
    /// user reads the explanation first (MacGuard product-language rule: never show a raw error alone).
    static func failure(_ es: String, _ en: String, detail: String) -> String {
        tr(es, en) + " " + tr("Detalle técnico: ", "Technical detail: ") + detail
    }
}
