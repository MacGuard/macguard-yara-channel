# Firma de código, notarización y Gatekeeper

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [Roadmap](ES-Roadmap) · [Installer Auditor](ES-App-InstallerAuditor) · [MacFirewallGuard](ES-App-Firewall) · [Network Extension](ES-Tech-NetworkExtension)

## En 30 segundos

Tres piezas que se confunden a menudo:

- **Firma de código**: el desarrollador pone un sello digital a su app. Dice quién la firmó y permite saber si se alteró después.
- **Notarización**: el desarrollador envía la app firmada a Apple, que la revisa automáticamente y devuelve un "ticket". Es una revisión automática, **no** una garantía de que no haya malware.
- **Gatekeeper**: la parte de macOS que, al abrir algo descargado, comprueba el sello y la notarización y pide tu aprobación {{ev:EV-EC-78}}.

## Un ejemplo cotidiano

La firma es el sello de lacre de una carta: dice de quién viene y si se abrió. La notarización es que correos revise el sobre en una máquina antes de entregarlo. Gatekeeper es el portero que mira ambas cosas cuando llegas a la puerta.

{{diagram:codesigning-chain}}

## Cómo se relacionan (técnico)

El flujo de notarización que sigue el proyecto (`SIGNING.md` de Installer Auditor, basado en la documentación de Apple; la página de Apple no se pudo leer completa desde aquí): firma con un certificado **Developer ID Application**, **hardened runtime**, `xcrun notarytool` para enviar, y grapar el ticket al `.app`, y comprobar con Gatekeeper {{ev:EV-EC-68}}. Gatekeeper verifica identidad del desarrollador, notarización e integridad al primer arranque, y sigue la procedencia de los archivos {{ev:EV-EC-78}}.

Una firma **ad hoc** (`codesign --sign -`) no tiene identidad de desarrollador: sirve para comprobar integridad local, pero no para que Gatekeeper acepte una descarga como notarizada.

## Dónde lo usa este proyecto

### Installer Auditor

- **Firma:** sus ayudantes `yara`/`yarac` van firmados **ad hoc** con hardened runtime.
- **Notarización:** la app y los ayudantes **no están notarizados**; falta Developer ID por falta de credenciales {{ev:EV-EC-73}}.
- **Lectura de firmas:** ejecuta `codesign --verify --strict` sobre sus propios ayudantes antes de usarlos {{ev:EV-EC-72}}.

### MacFirewallGuard

- **Lectura de firmas:** lee la firma real de los procesos mediante Security.framework para no fiarse del nombre {{ev:EV-EC-63}} {{ev:EV-EC-65}}.
- **Firma propia:** no hay compilación firmada ni notarizada.

### YARA Channel

- No firma apps; firma el canal de reglas con Sigstore, otro mecanismo {{ev:EV-YC-03}}.

### MacProcessGuard

- Nada: es un concepto {{ev:EV-EC-05}}.

El estado de firma de MacUSBGuard, MacCoreGuard y MacGuardDesignKit no se revisó para esta página: **no verificado**.

## Límites

- Una app firmada y notarizada puede ser maliciosa; la notarización no es certificación de ausencia de malware (el propio `SIGNING.md` de Installer Auditor lo recuerda).
- Una firma válida demuestra quién firmó y que no cambió, no que el código sea bueno.
- La notarización por sí sola no cubre un `.dmg` ya empaquetado: hay que firmar y comprobar el DMG final por separado (`SIGNING.md`).

## Quién más lo usa

- **Apple** define y aplica el mecanismo: Gatekeeper en macOS comprueba identidad, notarización e integridad. Misma tecnología. Fuente: guía de seguridad de plataforma de Apple, «Gatekeeper and runtime protection» {{ev:EV-EC-78}}.
- No se citan otros usuarios de esta tecnología: no se abrió ninguna fuente fiable que los nombre.

Nada de esto implica que Apple ni nadie use MacGuard. Lo que no se pudo respaldar con una fuente abierta se omite.
