# MacUSBGuard

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [Roadmap global](ES-Roadmap) · [Endpoint Security](ES-Tech-EndpointSecurity) · [DriverKit](ES-Tech-DriverKit)

## En 30 segundos

MacUSBGuard es un programa para Mac que decide qué dispositivos USB pueden funcionar **mientras la pantalla está bloqueada**. Distingue cuatro familias: teclados y ratones (HID), memorias de almacenamiento, adaptadores de red USB y llaves de seguridad físicas como las YubiKey. Por diseño, un dispositivo nuevo empieza como "no confiable" y, con el Mac bloqueado, se bloquearía del todo. Hoy el programa solo observa: no bloquea nada {{ev:EV-EC-20}}.

**Estado: en validación.** Hoy el programa se declara a sí mismo en modo **solo observación** (OBSERVE ONLY), nunca "activo", porque falta el permiso de Apple que permite bloquear teclados y ratones {{ev:EV-EC-01}} {{ev:EV-EC-02}}. No es un control de seguridad listo para producción.

No puede garantizar: bloquear un teclado malicioso hoy en este equipo, bloquear adaptadores de red USB (solo los detecta), ni proteger contra un atacante con el Mac desbloqueado.

## Un ejemplo cotidiano

Es como el portero de un edificio con una lista de inquilinos: de noche (Mac bloqueado) solo deja pasar a quien está en la lista y solo a las salas que le corresponden. La analogía no dice que el portero ya tenga las llaves de todas las puertas: aquí le falta el permiso del administrador del edificio (Apple).

## Diagrama

{{diagram:usb-decision-flow}}

## Paso a paso

1. Conectas un dispositivo. El programa lo inventaría (IOKit) y calcula una huella SHA-256 de sus datos canónicos {{ev:EV-EC-23}}.
2. Si el Mac está desbloqueado, no interviene.
3. Si está bloqueado, un resolutor de **dos etapas** decide primero sobre el dispositivo (no confiable implica denegar todo) y después sobre cada interfaz concedida; si la identidad cambia, bloquea la readmisión.
4. La decisión se traduce en una respuesta de Endpoint Security (HID) o en una denegación de montaje (el "dissent" de DiskArbitration) (almacenamiento).
5. Un resolutor global combina el estado de cada dominio: no puede llegar a "fuerte" si un dominio requerido solo observa.

## Arquitectura

Paquete SwiftPM (Swift 6, macOS 13 o superior), sin dependencias externas {{ev:EV-EC-26}}:

- `MacUSBGuardCore`: política y modelo puros, sin IOKit ni Endpoint Security.
- `MacUSBGuardStoragePlatform`: DiskArbitration e inventario IOKit.
- `MacUSBGuardPlatform`: sesión, tarjetas PIV y Endpoint Security.
- `MacUSBGuardPolicyDaemon`: demonio con privilegios; depende solo de Core y StoragePlatform, de modo que **no puede alcanzar** Endpoint Security ni la interfaz (lo impone el grafo de dependencias).
- `macusbguardctl` (línea de comandos), `MacUSBGuardApp` (SwiftUI) y `macusbguard-tests` (arnés de pruebas).

Frontera de confianza: app y CLI hablan con el demonio por XPC y este verifica la firma de código del llamante.

## Cómo funciona por dentro

| Pieza | Qué resuelve | Qué NO evita | Evidencia |
|---|---|---|---|
| `TwoStageAdmissionResolver` | Decide dispositivo y luego interfaz con el Mac bloqueado | Un dispositivo ya confiable que se comporte mal | `Core/TwoStageAdmissionResolver.swift` |
| `DeviceFingerprint` | Huella SHA-256 de una cadena canónica del dispositivo | Que un dispositivo imite todos los campos | `Core/DeviceFingerprint.swift` |
| `EndpointSecurityDecisionEngine` | Convierte un evento `AUTH_IOKIT_OPEN` en permitir/denegar con motivo; se niega a actuar sin identidad fiable | Nada en vivo: no hay permiso para ejecutarlo {{ev:EV-EC-21}} | `Core/EndpointSecurityDecisionEngine.swift` |
| `OverallProtectionResolver` | Estado global honesto por dominio | Falsos "verdes" por promedio | `Core/OverallProtectionResolver.swift` |
| `StorageAdmissionPolicy` | Aprueba o rechaza montajes con DiskArbitration | Que `diskarbitrationd` respete la denegación: sin probar | `Core/StorageAdmission.swift` |
| Desafío PIV | Prueba criptográfica de una llave (nonce firmado) frente a mera huella | Robo físico de la llave y su PIN | `Platform/SmartCardAuthenticationService.swift` |

Tecnologías con prueba en el código: Endpoint Security, DiskArbitration, IOKit, XPC, Security.framework, CryptoTokenKit, LocalAuthentication, SMAppService {{ev:EV-EC-23}}. **Solo planeadas o descartadas:** DriverKit (solo en ramas, ver más abajo), NetworkExtension (estudiada y descartada porque desactivaría otros filtros de contenido), CGEventTap (documentado como no elegido) {{ev:EV-EC-22}}.

## Pruebas

Las cifras son autoinformadas y **no las he ejecutado**. Hay un solo arnés propio (`macusbguard-tests`, 63 archivos) con unas 2.929 apariciones literales de `check(` (recuento estático; los bucles multiplican las ejecuciones reales) {{ev:EV-EC-25}}.

Hay dos líneas de desarrollo **divergentes** y sus cifras no se suman ni se comparan:

| Línea | Cifra declarada | Fuente |
|---|---|---|
| Tag `v1.0.0-rc1` (c2f9492) | 10.862 verificaciones, 0 fallos | informe de preparación del tag |
| Rama actual `ai/v1-release-integration` (78f7d37) | 816 checks, 0 fallos, 8 sin verificar | README de la rama (anterior a trabajo posterior) |

El tag **no es ancestro** de la rama actual {{ev:EV-EC-20}}. Cuál es "la" candidata a V1 no está resuelto en lo revisado. Pendientes documentados: pruebas de hardware HID y almacenamiento, validación con VoiceOver, auditoría visual y validación de instalación.

## Cómo comprobarlo tú

El código es privado: la comprobación corresponde al propietario. Comandos citados en su README: `./build.sh hardware-preflight`, `./scripts/storage-hardware-gate` y `macusbguardctl es-status`. No se ejecutaron para esta wiki.

## Límites

- Con el Mac de pruebas, HID está en estado parcial: falta el permiso restringido de Endpoint Security {{ev:EV-EC-02}}.
- Red USB: solo detección.
- Hay un DMG local `0.9.0-beta` cuyas notas dicen "Notarización: PASS", pero es una nota propia en una carpeta sin versionar: **no está verificada la notarización ni que se haya publicado** {{ev:EV-EC-24}}. El informe del tag rc1 dice, el mismo día, `NOT_NOTARIZED`. El README declara firma ad hoc.
- Ninguna otra aplicación MacGuard lo usa ni él usa otra: sin dependencias entre ellas {{ev:EV-EC-01}}.

## Estado

| Capacidad | Estado |
|---|---|
| Motor de política y resolutores | Implementado, probado por su propio arnés |
| Admisión de almacenamiento | Implementada; efecto real sin verificar |
| Bloqueo HID por Endpoint Security | Compila; en vivo sin verificar (falta el permiso) |
| Bloqueo de red USB | No implementado |
| DriverKit | Planificado/solo en ramas, fuera del producto |
| Notarización / publicación del DMG | No verificadas |

Siguiente objetivo documentado: crear el candidato V1; el próximo frente de trabajo está sin elegir {{ev:EV-EC-01}}.

## Dónde seguir

[Endpoint Security](ES-Tech-EndpointSecurity) · [DriverKit](ES-Tech-DriverKit) · [Firma de código](ES-Tech-CodeSigning) · [MacCoreGuard](ES-App-Core) · [Matriz de evidencias](ES-Evidence)
