# Interface rules for DMG Trust Auditor

Distilled from the MacGuard design kit and Apple's Human Interface Guidelines. The kit itself is no
longer vendored; only the parts this app uses live in `App/DesignSystem/`.

## Applied
- **Status is never color alone.** `MGStatusBadge` requires text and always shows an SF Symbol.
  `unknown` is never styled as success (`MGHealthStatus.permitsSuccessStyling`).
- **Contrast.** Status tints come from `MGSecurityTint`, which corrects hues to at least 4.5:1 (WCAG AA)
  against an opaque background. Do not draw tinted text over materials or translucency.
- **Headings.** Screen and section titles use `MGScreenHeader`/`MGSectionHeader`, which set the heading trait.
- **Typography and spacing** use `MGTypography` (semantic text styles, so Dynamic Type applies) and `MGSpacing`.
  No fixed point sizes.
- **Icon-only controls** are `InfoButton`, whose accessible name is the subject it explains.
- **Keyboard.** ⌘O choose file, ⌘R check for rule updates, Return verify, Esc closes the results sheet.
- **Appearance and language follow the system.** There is no forced light/dark switch; the language picker
  starts from the system language and persists the user's override.
- **Errors** are a plain-language sentence in the chosen language, followed by "Technical detail: …".
  Never show a raw error alone.
- **Honest scope.** Reports say what was not checked; a score is a heuristic, not a malware-free claim.
- **Motion.** None, on purpose. There is nothing for "Reduce Motion" to reduce; add a check if animation is introduced.

## Not decided (needs a human)
- Whether a feature that is *off* by choice and one that is *unavailable* on this Mac should share a tint.
- Per-component Dynamic Type limits at the largest accessibility sizes (the score numeral is the one to test).
- Cmd-F search and a table/filter pattern for long result lists (results are a bounded list today).
