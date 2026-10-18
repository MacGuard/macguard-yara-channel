import XCTest
@testable import DMGTrustAuditor

/// Guarantees ported from the MacGuard design kit that the UI relies on.
final class DesignSystemTests: XCTestCase {
    func testSpacingScale() {
        XCTAssertEqual([MGSpacing.xxxs, MGSpacing.xxs, MGSpacing.xs, MGSpacing.sm, MGSpacing.md, MGSpacing.lg, MGSpacing.xl, MGSpacing.xxl],
                       [1, 2, 4, 8, 12, 16, 20, 28])
    }
    func testHealthStatusVocabularyIsClosed() {
        // No silent extra tint: adding a case must be a reviewed decision.
        XCTAssertEqual(MGHealthStatus.allCases.count, 9)
    }
    func testOnlyProtectedPermitsSuccessStyling() {
        for status in MGHealthStatus.allCases { XCTAssertEqual(status.permitsSuccessStyling, status == .protected) }
    }
    func testEveryStatusHasASymbolSoColorIsNeverTheOnlySignal() {
        for status in MGHealthStatus.allCases { XCTAssertFalse(status.symbolName.isEmpty, "\(status)") }
    }
    func testSecurityTintContrastFloorIsWCAGAA() {
        XCTAssertEqual(MGSecurityTint.floor, 4.5)
    }
    func testUnknownIsNeverStyledAsSuccess() {
        XCTAssertFalse(MGHealthStatus.unknown.permitsSuccessStyling)
    }
}

final class AppLanguageTests: XCTestCase {
    func testFailureMessageLeadsWithPlainLanguageThenDetail() {
        AppLanguage.set(spanish: false)
        let m = AppLanguage.failure("Falló.", "It failed.", detail: "NSURLErrorDomain -1009")
        XCTAssertTrue(m.hasPrefix("It failed."))
        XCTAssertTrue(m.hasSuffix("Technical detail: NSURLErrorDomain -1009"))
        AppLanguage.set(spanish: true)
        XCTAssertTrue(AppLanguage.failure("Falló.", "It failed.", detail: "x").hasPrefix("Falló."))
        UserDefaults.standard.removeObject(forKey: AppLanguage.key)
    }
}
