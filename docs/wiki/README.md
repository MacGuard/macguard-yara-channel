# MacGuard wiki: sources and publication

The public GitHub Wiki is generated from these sources. Nothing is published automatically.

| Path | What |
|---|---|
| `es/<Id>.md`, `en/<Id>.md` | The text of each page, one file per language, same `<Id>` |
| `pages.json` | Ordered pages with section, title and summary per language |
| `provenance.json` | Evidence matrix: every status claim has an entry (source, date, commit or version, confidence, validation, state, class) |
| `diagrams/<name>.mmd` + `.json` | Wiki-only Mermaid diagrams (English labels) with title, text description and optional visible `legend` in both languages |
| `diagrams/<name>.es.mmd` | Spanish labels of the same diagram: mandatory for all 28 diagrams, including the 13 whose English source stays in `docs-src/diagrams/` (reused, never copied). The checker requires identical structure (nodes, edges, classes) |

Placeholders inside a page: `{{diagram:name}}` and `{{ev:EV-ID}}`. A raw Mermaid block in a page is rejected so both languages share one source.

## Rules

- A status claim about an application uses one of: concept, documented design, prototype, development, validation, release candidate, published, maintained, blocked (plus operational / implemented-not-deployed / planned for the YARA Channel).
- Every such claim links to its evidence entry. Without evidence the page says "not verified".
- Facts about private repositories enter `provenance.json` only as `REQUIERE REVISION` (state and review date, never commit ids, internal paths, identities, unpublished weaknesses or personal data). `CONFIDENCIAL` material never enters the repository.
- Pages describe private projects in public terms (purpose, phase, behavior). They never name internal paths, branches, local locations or infrastructure of those projects. The full internal references are kept in a private traceability matrix that is **not** in this repository. `python3 scripts/wiki_check.py --private-report` must list zero lines before publication.
- Paths of the public repository itself may be cited, because anyone can open them.
- Third-party rules keep their own licences; nothing here claims copyright over them. See `LICENSING-PROPOSAL.md` (a proposal, nothing is applied).
- Older documents that contradict these pages are tracked in a private matrix and corrected in a separate documentation pull request; the wiki work does not edit them.
- No dates, percentages or adoption claims without a source.

## Checks

```
python3 scripts/wiki_check.py            # parity ES/EN, links, evidence, diagrams (static), secrets, absolute claims, headings
python3 scripts/wiki_check.py --render   # also compiles every diagram (both languages) with the vendored Mermaid in headless Chrome and prints the width/text size at 390 px
python3 scripts/wiki_check.py --private-report   # must list 0 lines
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
