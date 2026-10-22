# Contribuir

[Inicio](ES-Home) · [Canal YARA](ES-YARA-Channel) · [Límites](ES-YARA-Limits) · [Glosario](ES-Glossary)

## En 30 segundos

Puedes ayudar ejecutando las pruebas, proponiendo un cambio como pull request o avisando de un fallo con una issue. Dos cosas **no** están todavía y esta página no finge lo contrario: el repositorio no tiene archivo de licencia y el canal de aviso de seguridad está planificado (lo definirá el mantenedor). Nunca publiques los detalles técnicos de una vulnerabilidad en una issue pública. {{ev:EV-YC-82}} {{ev:EV-YC-81}}

## Cómo comprobarlo tú: ejecutar las pruebas

Solo comandos que existen hoy en el repositorio:

```
python3 -m unittest discover -s tests
python3 -m unittest tests.test_tlog
```

- La primera línea es la suite de Python que la CI ejecuta en cada pull request. La CI instala antes el motor `yara` y `cosign`, porque `tests/test_verify_public_release.py` verifica la publicación real (interviene la red y un token de GitHub). Sin ellos algunas pruebas fallarán o no podrán ejecutarse; es una carencia del entorno, no un resultado que se pueda ignorar {{ev:EV-YC-88}}.
- La segunda línea ejecuta un solo módulo de pruebas; sirve para trabajar rápido en una zona. `tests.test_tlog` pasó al escribir esta página; el número de pruebas cambia con el código, así que no se cita.
- Las pruebas del servicio de revisión también se ejecutan en la CI con Node 24; sus órdenes están en el `package.json` de ese servicio. {{ev:EV-YC-88}}
- `scripts/web_check.sh [site-dir] [mode]` comprueba las páginas públicas en Chrome sin interfaz y necesita un sitio ya construido. El README menciona además `tests/tui_pty_check.py` y el esquema de Xcode `DMGTrustAuditor`; no se ejecutaron para esta página.

## Proponer un cambio

1. Haz una bifurcación (fork) o una rama, un cambio acotado y abre un **pull request** contra `main`. No hagas push directo a `main`.
2. La CI (`ci.yml`) se ejecuta en los pull requests: la suite de Python y las pruebas del servicio de revisión. Ejecútalas antes.
3. `.github/CODEOWNERS` nombra a `@MacGuard` como propietario de las rutas sensibles (flujos de trabajo, `config/`, `scripts/`, `tests/`, el código del servicio de revisión, la documentación de fuentes) {{ev:EV-YC-86}}.
4. Para las páginas de la wiki, sigue el proceso de [docs/wiki/README.md](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs/wiki/README.md): las páginas se generan desde `docs/wiki/` y nada se publica automáticamente.

**Sobre la protección de la rama.** Está prevista una protección reforzada de `main` (reglas de revisión antes de fusionar). {{ev:EV-YC-84}}

## Avisar de un fallo o pedir una función

Abre una [issue](https://github.com/MacGuard/macguard-yara-channel/issues). Las plantillas de issues **todavía no están en el repositorio** {{ev:EV-YC-83}}. Mientras tanto, cuenta qué hiciste, qué esperabas, qué ocurrió y el commit o la etiqueta de la publicación. No pegues secretos, tokens ni datos privados.

## Avisar de una vulnerabilidad

Canal de aviso de seguridad: **planificado**. La forma de comunicar una vulnerabilidad la definirá el mantenedor y aquí no se ofrece ninguna dirección ni formulario. **No publiques detalles técnicos de una vulnerabilidad en una issue ni en un pull request públicos.** {{ev:EV-YC-82}}

## Licencias y atribuciones

- **Este repositorio no tiene archivo LICENSE hoy.** Por eso esta wiki no concede ningún permiso para reutilizar el código {{ev:EV-YC-81}}.
- **Las reglas YARA vienen de terceros** (`Neo23x0/signature-base` y `Yara-Rules/rules`) con sus propias licencias, que se conservan en cada fuente. `config/policy.json` registra lo que el proyecto espera (Detection Rule License para la primera, GPL-2.0 para la segunda) y `scripts/licensing.py` lo compara en cada ejecución con lo que informa GitHub y con el texto de LICENSE; si no coinciden, todos los archivos de esa fuente quedan en cuarentena. Es una comprobación interna, no asesoría legal: lee la licencia de cada fuente y no des por hecho que las reglas se puedan reutilizar. Este proyecto no reclama derechos de autor sobre las reglas descargadas y las condiciones para redistribuirlas están pendientes de revisión legal {{ev:EV-YC-85}}.
- La biblioteca Mermaid incluida conserva su propio aviso en `web/vendor/mermaid-LICENSE.txt` {{ev:EV-YC-87}}.
- **Texto y diagramas de la wiki:** licencia pendiente de la decisión del propietario.

## Límites

Esta página describe el repositorio tal como se leyó, no lo que el propietario decida después. Se comprobó que los comandos de prueba existen; para esta página solo se ejecutaron `tests.test_tlog` y `tests.test_licensing`, no la suite completa.

## Estado

| Capacidad | Estado |
|---|---|
| Pull requests con CI (suite de Python, pruebas del servicio de revisión) | operativo {{ev:EV-YC-88}} |
| Protección reforzada de `main` | planificado {{ev:EV-YC-84}} |
| Plantillas de issues | planificado (no están en el repositorio) {{ev:EV-YC-83}} |
| Canal de aviso de seguridad | planificado {{ev:EV-YC-82}} |
| Archivo de licencia del repositorio | ausente {{ev:EV-YC-81}} |
