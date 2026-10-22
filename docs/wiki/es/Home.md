# Bienvenida a MacGuard

## En 30 segundos

MacGuard es una familia de herramientas para proteger un Mac. Cada una vigila una cosa distinta: los instaladores que descargas, los dispositivos USB, las conexiones de red. Una de ellas, **YARA Channel**, reparte las "listas de pistas" (reglas YARA) con las que se reconocen archivos sospechosos, y las firma para que cualquiera pueda comprobar que son las publicadas y que no cambiaron después de firmarse. Ayudan a reconocer patrones conocidos; no garantizan que un archivo sea seguro.

Esta wiki explica qué hace cada pieza, cómo funciona y **en qué punto de desarrollo está de verdad**. Si algo no está probado, lo decimos.

## Un ejemplo cotidiano

Piensa en la seguridad de una casa: una cerradura, una alarma y alguien que vigila la puerta. Ninguna basta sola y ninguna promete parar a todos los ladrones. MacGuard es igual: varias piezas pequeñas, cada una con un trabajo y con límites claros.

## El mapa de un vistazo

{{diagram:ecosystem-map-1-supply}}

{{diagram:ecosystem-map-2-planned}}

{{diagram:ecosystem-map-3-others}}

- **YARA Channel**: Reúne, valida y publica reglas YARA firmadas y verificables. *Estado: Publicado* {{ev:EV-YC-02}}
- **Installer Auditor**: Revisa instaladores con esas reglas antes de abrirlos. *Estado: En desarrollo* {{ev:EV-YC-09}}
- **MacUSBGuard**: Vigila los dispositivos USB que se conectan. *Estado: En validación* {{ev:EV-EC-01}}
- **MacFirewallGuard**: Observa las conexiones de red y aplicará una política. *Estado: En desarrollo* {{ev:EV-EC-03}}
- **MacProcessGuard**: Identificaría qué programa hace cada cosa. *Estado: Solo concepto* {{ev:EV-EC-05}}
- **MacCoreGuard**: Base común para guardar evidencias verificables. *Estado: Prototipo* {{ev:EV-EC-06}}
- **MacGuardDesignKit**: Piezas de interfaz compartidas entre las apps. *Estado: En desarrollo* {{ev:EV-EC-07}}

## Qué existe hoy

- **Publicado:** el canal de reglas YARA, con firma Sigstore y un registro de transparencia verificable {{ev:EV-YC-03}} {{ev:EV-YC-04}}.
- **Funcionando, de uso interno:** el panel privado donde se revisan las reglas en cuarentena {{ev:EV-YC-05}}.
- **Ninguna otra aplicación está publicada como producto final** según la evidencia revisada.

## En qué estamos trabajando

- YARA Channel: retiradas persistentes y control de admisión de fuentes, implementados en el repositorio y aún no activos en producción {{ev:EV-YC-06}} {{ev:EV-YC-07}}, y el archivo histórico en tres proveedores, que **aún no es operativo** {{ev:EV-YC-08}}.
- MacFirewallGuard y MacUSBGuard: avanzar las pruebas que dependen de permisos de Apple que aún faltan {{ev:EV-EC-02}} {{ev:EV-EC-04}}.

## Siguiente hito

No hay fechas comprometidas. El siguiente paso de cada aplicación, sus bloqueos y sus dependencias están en el [Roadmap global](ES-Roadmap).

## Dónde seguir

- [Ecosistema: capas y relaciones](ES-Ecosystem)
- [Roadmap global](ES-Roadmap)
- [YARA Channel en profundidad](ES-YARA-Channel)
- Fichas: [MacUSBGuard](ES-App-USB), [MacFirewallGuard](ES-App-Firewall), [MacProcessGuard](ES-App-Process), [MacCoreGuard](ES-App-Core), [Installer Auditor](ES-App-InstallerAuditor), [DesignKit](ES-App-DesignKit)
- Tecnologías: [YARA](ES-Tech-YARA), [Sigstore](ES-Tech-Sigstore), [árboles de Merkle](ES-Tech-Merkle), [copias S3](ES-Tech-S3-Backups), [Endpoint Security](ES-Tech-EndpointSecurity), [DriverKit](ES-Tech-DriverKit), [Network Extension](ES-Tech-NetworkExtension), [Firma de código](ES-Tech-CodeSigning)
- [Glosario](ES-Glossary) · [Cómo contribuir](ES-Contribute)
- [Matriz de evidencias](ES-Evidence)
