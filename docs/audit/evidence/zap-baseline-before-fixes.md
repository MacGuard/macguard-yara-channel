# ZAP baseline (passive spider, 3 minutes) on the two public hosts, BEFORE the fixes of the final audit

Tool: zaproxy/zap-stable docker image, `zap-baseline.py -t URL -m 3`; only GET requests, own domains, run 2026-10-19. Raw JSON/HTML reports are not kept (4 MB); re-run to reproduce.

| Host | Risk | Alert | Instances |
|---|---|---|---|
| github.io | Informational | Information Disclosure - Suspicious Comments | 2 |
| github.io | Informational | Modern Web Application | 5 |
| github.io | Informational | Re-examine Cache-control Directives | 5 |
| github.io | Informational | Retrieved from Cache | 9 |
| github.io | Informational | Storable and Cacheable Content | 5 |
| github.io | Low | Cross-Origin-Embedder-Policy Header Missing or Invalid | 5 |
| github.io | Low | Cross-Origin-Opener-Policy Header Missing or Invalid | 5 |
| github.io | Low | Permissions Policy Header Not Set | 5 |
| github.io | Low | Strict-Transport-Security Header Not Set | 5 |
| github.io | Low | Timestamp Disclosure - Unix | 5 |
| github.io | Low | X-Content-Type-Options Header Missing | 5 |
| github.io | Medium | Application Error Disclosure | 6 |
| github.io | Medium | CSP: Failure to Define Directive with No Fallback | 5 |
| github.io | Medium | CSP: style-src unsafe-inline | 5 |
| github.io | Medium | Content Security Policy (CSP) Header Not Set | 5 |
| github.io | Medium | Cross-Domain Misconfiguration | 5 |
| github.io | Medium | Directory Browsing | 1 |
| github.io | Medium | Missing Anti-clickjacking Header | 5 |
| github.io | Medium | Source Code Disclosure - ASP | 1 |
| github.io | Medium | Source Code Disclosure - PHP | 3 |
| github.io | Medium | Source Code Disclosure - Perl | 1 |
| github.io | Medium | Source Code Disclosure - Python | 1 |
| github.io | Medium | Source Code Disclosure - SQL | 6 |
| github.io | Medium | Vulnerable JS Library | 1 |
| pages.dev | Informational | Information Disclosure - Suspicious Comments | 2 |
| pages.dev | Informational | Modern Web Application | 5 |
| pages.dev | Informational | Non-Storable Content | 4 |
| pages.dev | Informational | Re-examine Cache-control Directives | 5 |
| pages.dev | Informational | Storable but Non-Cacheable Content | 5 |
| pages.dev | Low | Cross-Origin-Embedder-Policy Header Missing or Invalid | 5 |
| pages.dev | Low | Cross-Origin-Opener-Policy Header Missing or Invalid | 5 |
| pages.dev | Low | Permissions Policy Header Not Set | 5 |
| pages.dev | Low | Strict-Transport-Security Header Not Set | 5 |
| pages.dev | Low | Timestamp Disclosure - Unix | 5 |
| pages.dev | Medium | Application Error Disclosure | 6 |
| pages.dev | Medium | Content Security Policy (CSP) Header Not Set | 5 |
| pages.dev | Medium | Cross-Domain Misconfiguration | 5 |
| pages.dev | Medium | Directory Browsing | 1 |
| pages.dev | Medium | Missing Anti-clickjacking Header | 5 |
| pages.dev | Medium | Source Code Disclosure - ASP | 1 |
| pages.dev | Medium | Source Code Disclosure - PHP | 3 |
| pages.dev | Medium | Source Code Disclosure - Perl | 1 |
| pages.dev | Medium | Source Code Disclosure - Python | 1 |
| pages.dev | Medium | Source Code Disclosure - SQL | 6 |
| pages.dev | Medium | Vulnerable JS Library | 1 |
