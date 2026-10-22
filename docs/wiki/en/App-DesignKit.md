# MacGuardDesignKit

[Home](EN-Home) · [Ecosystem](EN-Ecosystem) · [Global roadmap](EN-Roadmap) · [MacUSBGuard](EN-App-USB)

## In 30 seconds

MacGuardDesignKit is a **library of SwiftUI interface components**: buttons, cards, tables, status badges, search bars and the look of charts. It is **not a protection product**: it does not watch, block or detect anything. Its goal is that all MacGuard applications look and behave the same, so a green "protected" badge means the same thing in all of them {{ev:EV-EC-30}}.

**State: development** (version 0.3.1; the library itself says it is not 1.0 because much of the 16-component catalog is not built yet). Today no application imports it, according to the package files I read {{ev:EV-EC-07}}.

## An everyday example

It is the parts box of one construction set: if every house is built from the same parts, a red roof means the same thing everywhere. But the parts box builds no house by itself and does not make one safer.

## Diagram

{{diagram:ecosystem-map}}

On the map it sits among the "shared building blocks": a supporting piece that applications could use, with no security logic of its own.

## Step by step

1. An application declares the package as a SwiftPM dependency.
2. It builds its screens with `MG...` components (`MGCard`, `MGStatusBadge`, `MGTable`...).
3. The components apply the design system's colors, typography and spacing.
4. A heuristic script (`Scripts/anti-drift-check.sh`) can scan the application's code for hand-written colors or font sizes that bypass the system.

## Architecture

One library target plus one test target; swift-tools 5.9, macOS 13 or later, **no external dependencies** {{ev:EV-EC-31}}. Folders: Charts, Colors, Components, Detail, Feedback, Icons, Search, Shell, Spacing, State, Status, Table, Theme, Typography. It imports only SwiftUI, AppKit, CoreGraphics and Foundation: it **does not use the Charts framework**; charts are styling only.

**Hard constraint** (documented and checkable with a `grep` in its README): it must not depend on DriverKit, NetworkExtension, EndpointSecurity or any internal module of the applications. That is why it needs no special permissions or provisioning profiles.

## Under the hood

| Piece | Problem | How | Evidence |
|---|---|---|---|
| `MGSecurityTint` | System colors (green, orange, red, blue) fail contrast on some backgrounds | Blends the color toward black or white in 5% steps until a 4.5:1 contrast is reached (WCAG 2.2 AA criterion) | `Colors/MGSecurityTint.swift` |
| `MGHealthStatus` | Inconsistent states across apps | One vocabulary of 9 cases, each with color, SF symbol and word | `Status/MGHealthStatus.swift` |
| `MGStatusBadge` | Badges that rely on color alone | The `text:` parameter is not optional: a color-only badge cannot be created | `Components/MGStatusBadge.swift` |
| `MGDestructiveButton` + `MGConfirmationDialog` | Destructive actions without confirmation | The confirmation cannot be skipped | `Components/MGButtons.swift` |
| `MGTable` | Consistent sortable tables | Generic table over `Identifiable` data; 0.3.1 fixed the accessibility grouping of rows | `Table/MGTable.swift` |

What it does **not** guarantee: that an application using it is accessible (that depends on how it is used), nor does it replace human VoiceOver validation. The anti-drift script is heuristic and can give false positives and negatives.

## Tests

One test target with 3 files and 26 `test` functions (static count, **not run**); no execution results are documented in the repository {{ev:EV-EC-32}}. The README mentions about 15 anti-drift findings in its own sources that were left unmarked.

## Check it yourself

The repository is private. Per its README: `swift build` and `swift test`, plus the hard-constraint `grep`. They were not run for this wiki.

## Limits

- The README keeps stale text (version 0.1.0 and "not yet published") while the code declares 0.3.1; I did not verify that the remote repository is reachable or that tags are published.
- Five design decisions await human sign-off {{ev:EV-EC-32}}.
- It is not a security control and protects no one by itself.

## State

| Capability | State |
|---|---|
| Tokens, base components, shell, table, search, states | Implemented (0.1.0 to 0.3.1), not verified by execution |
| Rest of the 16-component catalog | Planned |
| Version 1.0 | Planned: requires stability and at least two products using it (today zero) |

## Further reading

[MacUSBGuard](EN-App-USB) · [Global roadmap](EN-Roadmap) · [Evidence matrix](EN-Evidence)
