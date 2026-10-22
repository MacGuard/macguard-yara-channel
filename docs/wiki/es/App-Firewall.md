# MacFirewallGuard

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [Roadmap](ES-Roadmap) · [Network Extension](ES-Tech-NetworkExtension) · [Firma y notarización](ES-Tech-CodeSigning) · [MacProcessGuard](ES-App-Process)

## En 30 segundos

MacFirewallGuard es un programa para macOS pensado para **observar qué apps se conectan a la red y, más adelante, aplicar reglas** sobre esas conexiones. Su idea central: una app puede llamarse "Safari" sin serlo, así que el programa mira la **firma de código real** y no se fía del nombre. Si falta evidencia, responde "no lo sé", nunca "permitido".

**Hoy no puede bloquear nada**: Apple no ha concedido a este proyecto el permiso (entitlement) de Network Extension {{ev:EV-EC-60}}. Es un motor de observación y de políticas, en estado **desarrollo** {{ev:EV-EC-03}}. No es un cortafuegos operativo y no se debe usar como protección.

## Un ejemplo cotidiano

Es como un portero con una lista de invitados que comprueba el DNI y no la palabra del visitante. El portero ya sabe leer DNIs y aplicar la lista, pero todavía no tiene llave para cerrar la puerta: si la lista dice "no pasa", solo puede anotar "no tengo llave".

## Diagrama

{{diagram:firewall-decision}}

## Paso a paso

1. Entra un flujo de red observado (hoy, de entrada sintética o de prueba: nunca se capturó un paquete real {{ev:EV-EC-64}}).
2. `CodeSignatureResolver` averigua la firma real del proceso.
3. `PolicyEngine` evalúa las reglas: coincide, no coincide o **indeterminado** si falta evidencia.
4. `EnforcementResolver` convierte la decisión en acción. Sin el permiso, un BLOCK acaba como `ACTION=UNAVAILABLE(ENTITLEMENT_MISSING)` {{ev:EV-EC-60}}.
5. Se crea un evento de auditoría y se guarda en una cola local; su envío a MacCoreGuard solo se ha probado contra un simulacro {{ev:EV-EC-04}}.

## Cómo funciona por dentro

Arquitectura por capas (de `Package.swift`) {{ev:EV-EC-63}}:

| Capa | Función |
|---|---|
| `MacFirewallGuardCore` | Dominio puro (flujos, políticas, DNS, correlación, red) |
| `MacFirewallGuardAudit` | Eventos canónicos y cola duradera (`DurableAuditSpool`) |
| `MacFirewallGuardPlatform` | Única capa que toca marcos de Apple (Security, Network, SystemConfiguration, NetworkExtension como puente de traducción) |
| `CBPFShim` | Pequeño módulo C con constantes de BPF |
| `MacFirewallGuardUI` y `MacFirewallGuardApp` | App SwiftUI (usa MacGuardDesignKit, única dependencia externa) |
| `macfirewallguardctl` | CLI de solo lectura: `capabilities`, `privileges`, `events`, `adversarial`, `preflight`, `explain` |

Algoritmos con código que los prueba (nombre, problema, evidencia):

- **`PolicyEngine.evaluate`**: decide con tres valores (coincide / no coincide / indeterminado). Evita tratar "sin datos" como "permitido". Archivo `Sources/MacFirewallGuardCore/Policy/PolicyEngine.swift`.
- **`CodeSignatureResolver`**: resuelve la identidad de firma desde un audit token, un pid o una ruta (`Platform/CodeSignatureResolver.swift`). No detecta inyección de código: su documento de amenazas lo asigna a MacProcessGuard, que no existe.
- **`DNSWireParser` y `TLSClientHelloParser`** (Core) y **`QUICInitialPacketParser`** (Platform): leen DNS, SNI de TLS y QUIC. Solo se han probado con bytes de prueba.
- **`NetworkIntegrityRuleEngine`** (F2-NIM): detecta cambios de VPN, rutas o DNS; solo modos observar y alertar.
- **Sensor BPF** opcional (`BPFDevice`, `BPFCaptureSensor`): en la máquina de desarrollo el acceso se denegó por permisos {{ev:EV-EC-64}}.

### Transporte hacia MacCoreGuard: XPC o socket

La documentación de arquitectura y la matriz de capacidades hablan de "XPC autenticado" como diseño objetivo del lado de MacCore. **El código del cliente usa un socket Unix** (`AF_UNIX`, `SOCK_STREAM`, mensajes JSON con longitud) en `Platform/MacCoreGuardIPCClient.swift`; un comentario de `MacCoreAuditClient.swift` dice que el transporte "es NSXPC" como intención futura, pero no hay implementación XPC en las fuentes de producción {{ev:EV-EC-61}}. El cliente comprueba, con la credencial del kernel (`LOCAL_PEERPID`), la firma del proceso al otro lado del socket. Esa comprobación y el servidor se ejercitan solo con un servidor simulado de pruebas.

## Cómo comprobarlo tú

El repositorio es privado, así que no hay comandos públicos. En una copia con acceso: `swift run macfirewallguardctl explain` y `swift run macfirewallguardctl preflight` (existen en el README). No se ejecutó nada para escribir esta página: los datos son lectura estática del commit `052007e`.

## Pruebas: qué cifras hay y de dónde salen

El README dice "661 deterministic + 10 live checks", pero está **desactualizado** (cabecera "FOUNDATION_V1") {{ev:EV-EC-62}}. Las cifras por documento, ninguna re-medida:

| Cifra | Procede de |
|---|---|
| 661 deterministas | `docs/testing/TESTING_V1.md` y README (fase F1-A) |
| 1038 deterministas | total fijado en el arnés `verify` (`EXPECTED_DETERMINISTIC_TOTAL`) |
| 1160 superadas (1043 + 70 + 47) | `docs/release/F2A_CLOSEOUT.md` |
| 78/78 | `docs/architecture/F2_NIM_ARCHITECTURE.md`, suite `macfirewallguard-nim-tests` |

Pendiente según su propio cierre: ninguna captura real de paquetes, ni ejecución con TSan, ni fuzzing guiado por cobertura, ni pruebas de rendimiento {{ev:EV-EC-64}}. El README también dice "cero dependencias externas", ya falso (usa MacGuardDesignKit).

## Límites

- No bloquea ni observa tráfico real hoy {{ev:EV-EC-60}}.
- No hay compilación firmada ni notarizada, y `FIREWALL_PRODUCTION_READY = NO` {{ev:EV-EC-65}}.
- Coexistir con otros filtros de contenido ya instalados es un bloqueo documentado sin resolver.
- No sustituye a MacProcessGuard (identidad de proceso) ni a MacCoreGuard (registro verificable): ninguno existe como servicio {{ev:EV-EC-05}}.

## Estado

| Capacidad | Estado |
|---|---|
| Motor de políticas, modelo de flujos, resolución de firma, app SwiftUI, CLI | Implementado, no desplegado |
| Cliente MacCoreGuard (socket Unix) | Implementado, probado solo con simulacro |
| Observación y bloqueo reales (extensión del sistema) | Planificado, bloqueado por el permiso de Apple |
| Endpoint Security, PKTAP, Rust | Planificado o fuera de este repositorio; sin código |

Fases: F1-A, F1-B y GUI-V1 cerradas; F2-A parcial (`F2A_COMPLETE = NO`); F2-NIM integrada {{ev:EV-EC-04}}. Sin fechas. Más: [Network Extension](ES-Tech-NetworkExtension), [Firma de código](ES-Tech-CodeSigning).
