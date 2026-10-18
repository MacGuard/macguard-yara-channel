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

> **ACTUAL** El servicio de cuarentena está implementado y probado con un servidor de desarrollo local, pero **no está desplegado** en producción: faltan credenciales de Cloudflare Workers/D1 y una aplicación OAuth de GitHub. Mientras tanto la cuarentena se aplica en el pipeline y solo se publica lo que supera todos los controles automáticos.

## Límites de confianza

{{diagram:trust-boundaries}}

Las fuentes son entrada no fiable. Lo relativo a reglas no publicadas (nombres, hallazgos, contenido) no sale del job privado salvo hacia el servicio privado; los artefactos, registros y el sitio públicos llevan solo cifras.
