# Bienvenida a MacGuard

## En 30 segundos

MacGuard es una familia de herramientas para proteger un Mac. Cada una vigila una cosa distinta: los instaladores que descargas, los dispositivos USB, las conexiones de red. Una de ellas, **YARA Channel**, reparte las "listas de pistas" (reglas YARA) con las que se reconocen archivos sospechosos, y lo hace de forma que cualquiera puede comprobar que no se han manipulado.

Esta wiki explica qué hace cada pieza, cómo funciona y **en qué punto de desarrollo está de verdad**. Si algo no está probado, lo decimos.

## El mapa de un vistazo

{{diagram:ecosystem-map}}

| Aplicación | Qué hace, en una frase | Estado | Evidencia |
|---|---|---|---|
| YARA Channel | Reúne, valida y publica reglas YARA firmadas y verificables | Publicado | {{ev:EV-YC-02}} |
| Installer Auditor | Revisa instaladores con esas reglas antes de abrirlos | En desarrollo | {{ev:EV-YC-09}} |
| MacUSBGuard | Vigila los dispositivos USB que se conectan | En validación | {{ev:EV-EC-01}} |
| MacFirewallGuard | Observa las conexiones de red y aplicará una política | En desarrollo | {{ev:EV-EC-03}} |
| MacProcessGuard | Identificaría qué programa hace cada cosa | Solo concepto | {{ev:EV-EC-05}} |
| MacCoreGuard | Base común para guardar evidencias verificables | Prototipo | {{ev:EV-EC-06}} |
| MacGuardDesignKit | Piezas de interfaz compartidas entre las apps | En desarrollo | {{ev:EV-EC-07}} |

## Qué existe hoy

- **Publicado:** el canal de reglas YARA, con firma Sigstore y un registro de transparencia verificable {{ev:EV-YC-03}} {{ev:EV-YC-04}}.
- **Funcionando, de uso interno:** el panel privado donde se revisan las reglas en cuarentena {{ev:EV-YC-05}}.
- **Ninguna otra aplicación está publicada como producto final** según la evidencia revisada.

## En qué estamos trabajando

- YARA Channel: retiradas persistentes y propuestas de fuentes, ya escritas y probadas pero todavía sin desplegar {{ev:EV-YC-06}} {{ev:EV-YC-07}}, y el archivo histórico en tres proveedores, que **aún no es operativo** {{ev:EV-YC-08}}.
- MacFirewallGuard y MacUSBGuard: avanzar las pruebas que dependen de permisos de Apple que aún faltan {{ev:EV-EC-02}} {{ev:EV-EC-04}}.

## Siguiente hito

No hay fechas comprometidas. El siguiente paso de cada aplicación, sus bloqueos y sus dependencias están en el [Roadmap global](ES-Roadmap).

## Dónde seguir

- [Ecosistema: capas y relaciones](ES-Ecosystem)
- [Roadmap global](ES-Roadmap)
- [YARA Channel en profundidad](ES-YARA-Channel)
- Fichas: [MacUSBGuard](ES-App-USB), [MacFirewallGuard](ES-App-Firewall), [MacProcessGuard](ES-App-Process), [MacCoreGuard](ES-App-Core), [Installer Auditor](ES-App-InstallerAuditor), [DesignKit](ES-App-DesignKit)
- [Matriz de evidencias](ES-Evidence)
