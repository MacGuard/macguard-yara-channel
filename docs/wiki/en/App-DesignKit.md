# MacGuardDesignKit

[Home](EN-Home) · [Ecosystem](EN-Ecosystem) · [Global roadmap](EN-Roadmap) · [MacUSBGuard](EN-App-USB)

## In 30 seconds

MacGuardDesignKit is a **SwiftUI component library shared by the apps**: buttons, cards, tables, status badges, search bars and the look of charts. It is **not a protection product**: it does not watch, block or detect anything. Its goal is that all MacGuard applications look and behave the same, so a green "protected" badge means the same thing in all of them {{ev:EV-EC-30}}.

**State: development** (a pre-1.0 version; the library itself says it is not 1.0 because much of its planned component catalog is not built yet). MacFirewallGuard's interface layer imports it; MacUSBGuard has not adopted it yet, and the library's README still says it has no consumers, which is stale {{ev:EV-EC-07}}.

## An everyday example

It is the parts box of one construction set: if every house is built from the same parts, a red roof means the same thing everywhere. But the parts box builds no house by itself and does not make one safer.

## Diagram

{{diagram:ecosystem-map}}

On the map it sits among the "shared building blocks": a supporting piece that applications could use, with no security logic of its own.

## Step by step

1. An application declares the package as a SwiftPM dependency.
2. It builds its screens with the library's ready-made components (cards, status badges, tables...).
3. The components apply the design system's colors, typography and spacing.
4. A heuristic check script can scan the application's code for hand-written colors or font sizes that bypass the system.

## Architecture

One library plus its tests, for macOS 13 or later, **with no external dependencies** {{ev:EV-EC-31}}. It is organized by theme (colors, spacing, typography, components, tables, search, states, charts styling). It imports only Apple's UI and graphics frameworks and **does not use the Charts framework**; charts are styling only.

**Hard constraint** (documented and checkable): it must not depend on system-level security technologies or on any internal module of the applications. That is why it needs no special permissions or provisioning profiles.

## Under the hood

| Piece | Problem | How | Evidence |
|---|---|---|---|
| Accessible security colors | System colors (green, orange, red, blue) fail contrast on some backgrounds | Adjusts the color toward black or white in small steps until a readable contrast is reached (WCAG 2.2 AA criterion) | See the [evidence matrix](EN-Evidence) |
| Shared health vocabulary | Inconsistent states across apps | One vocabulary of states, each with color, symbol and word | See the [evidence matrix](EN-Evidence) |
| Status badge | Badges that rely on color alone | The text is mandatory: a color-only badge cannot be created | See the [evidence matrix](EN-Evidence) |
| Destructive button and confirmation dialog | Destructive actions without confirmation | The confirmation cannot be skipped | See the [evidence matrix](EN-Evidence) |
| Sortable table | Consistent sortable tables | Generic table over identifiable data, with accessible grouping of rows | See the [evidence matrix](EN-Evidence) |

What it does **not** guarantee: that an application using it is accessible (that depends on how it is used), nor does it replace human VoiceOver validation. The anti-drift script is heuristic and can give false positives and negatives.

## Tests

The library has a small test target (static reading, **not run**); no execution results are documented in the repository {{ev:EV-EC-32}}. The README acknowledges some anti-drift findings in its own sources that were left unmarked.

## Check it yourself

The repository is private. Its README describes a build and test run plus a dependency check; they were not run for this wiki.

## Limits

- The README keeps stale text (an older version and "not yet published") while the code declares a newer one; it was not verified that the remote repository is reachable or that tags are published.
- Some design decisions await human sign-off {{ev:EV-EC-32}}.
- It is not a security control and protects no one by itself.

## State

| Capability | State |
|---|---|
| Tokens, base components, shell, table, search, states | Implemented (pre-1.0), not verified by execution |
| Rest of the planned component catalog | Planned |
| Version 1.0 | Planned: requires stability and at least two products using it (today one) |

## Further reading

[MacUSBGuard](EN-App-USB) · [Global roadmap](EN-Roadmap) · [Evidence matrix](EN-Evidence)
