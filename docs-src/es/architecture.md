---
title: Arquitectura
summary: Los componentes del canal y cómo se conectan de extremo a extremo.
---
## Vista de conjunto

El flujo tiene dos mitades: un pipeline privado que decide qué se publica y una cadena pública firmada que cualquiera puede verificar. El punto de decisión es `decide.py`: nada llega a la firma sin pasar por él.

{{diagram:architecture}}

## Componentes

| Componente | Qué hace | Dónde |
|---|---|---|
| `daily.yml` | Ejecución diaria 03:17 UTC o manual: recoge, clasifica, mide, decide y solicita la publicación. | `.github/workflows/daily.yml` |
| `publish.yml` | Firma y publica la release; entorno `stable-signing-auto` si `AUTO_PUBLISH=true`, `stable-signing` con aprobador humano si no. | `.github/workflows/publish.yml` |
| `site.yml` | Construye y verifica el sitio, lo despliega y comprueba la URL pública. | `.github/workflows/site.yml` |
| Servicio de cuarentena | Almacén privado y panel de revisión (Cloudflare Worker + D1). | `admin/worker/` |
| MacGuard | GUI, TUI y CLI con un único motor compartido. | `DMGTrustAuditor/DMGTrustAuditor/Core/` |

> **ACTUAL** El servicio de cuarentena y su panel están desplegados y el pipeline lee sus decisiones. La cuarentena también se aplica dentro del pipeline y solo se publica lo que supera todos los controles automáticos. Las políticas persistentes, los anclajes de auditoría y las propuestas de fuentes (migraciones 0003 a 0005) están en `main` pero no desplegados.

## Límites de confianza

{{diagram:trust-boundaries}}

Las fuentes son entrada no fiable. Lo relativo a reglas no publicadas (nombres, hallazgos, contenido) no sale del job privado salvo hacia el servicio privado; los artefactos, registros y el sitio públicos llevan solo cifras.
