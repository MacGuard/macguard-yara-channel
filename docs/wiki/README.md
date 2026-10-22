# MacGuard wiki: sources and publication

The public GitHub Wiki is generated from these sources. Nothing is published automatically.

| Path | What |
|---|---|
| `es/<Id>.md`, `en/<Id>.md` | The text of each page, one file per language, same `<Id>` |
| `pages.json` | Ordered pages with section, title and summary per language |
| `provenance.json` | Evidence matrix: every status claim has an entry (source, date, commit or version, confidence, validation, state, class) |
| `diagrams/<name>.mmd` + `.json` | Wiki-only Mermaid diagrams with title and text description in both languages. Diagrams of the public docs site (`docs-src/diagrams/`) are reused, never copied |

Placeholders inside a page: `{{diagram:name}}` and `{{ev:EV-ID}}`. A raw Mermaid block in a page is rejected so both languages share one source.

## Rules

- A status claim about an application uses one of: concept, documented design, prototype, development, validation, release candidate, published, maintained, blocked (plus operational / implemented-not-deployed / planned for the YARA Channel).
- Every such claim links to its evidence entry. Without evidence the page says "not verified".
- Facts about private repositories enter `provenance.json` only as `REQUIERE REVISION` (state and commit id, never internal paths, identities, unpublished weaknesses or personal data). `CONFIDENCIAL` material never enters the repository.
- No dates, percentages or adoption claims without a source.

## Checks

```
python3 scripts/wiki_check.py            # parity ES/EN, links, evidence, diagrams (static), secrets, absolute claims, headings
python3 scripts/wiki_check.py --render   # also compiles every diagram with the vendored Mermaid in headless Chrome
python3 scripts/wiki_build.py --out DIR  # writes the flat ES-*.md / EN-*.md files, _Sidebar.md, _Footer.md
python3 -m unittest tests.test_wiki
```

The Python suite of CI (`tests/test_wiki.py`) runs the static checks on every pull request. GitHub renders Mermaid with its own version: the first real check of rendering is the first publication to the Wiki.

## Publishing to the GitHub Wiki (manual, after the owner's approval)

1. Merge the pull request that changes `docs/wiki/`.
2. In a clean directory: `python3 scripts/wiki_build.py --out /tmp/wiki-out` on the merged `main`.
3. Enable the Wiki once in the repository settings (Features), then create its first page in the browser so the Wiki repository exists.
4. `git clone git@github.com:MacGuard/macguard-yara-channel.wiki.git`, copy the contents of `/tmp/wiki-out` into it, review `git diff`, and `git commit` / `git push` as the owner. No token is stored anywhere and no automation pushes to the Wiki.
5. Open the published pages on a phone and in dark mode and check that every diagram renders.
