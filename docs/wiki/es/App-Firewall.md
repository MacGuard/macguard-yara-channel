# MacFirewallGuard

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [Roadmap](ES-Roadmap) · [Network Extension](ES-Tech-NetworkExtension) · [Firma y notarización](ES-Tech-CodeSigning) · [MacProcessGuard](ES-App-Process)

## En 30 segundos

MacFirewallGuard es un programa para macOS pensado para **observar qué apps se conectan a la red y, más adelante, aplicar reglas** sobre esas conexiones. Su idea central: una app puede llamarse "Safari" sin serlo, así que el programa lee la **firma de código real** de los procesos en lugar de fiarse del nombre. Si falta evidencia, el motor responde "indeterminado" y no lo trata como "permitido" (qué acción final se aplicaría con la política real aún no está probado).

**Hoy no hay bloqueo real**: ningún permiso (entitlement) de Network Extension consta como utilizable para este proyecto {{ev:EV-EC-60}}. Es un motor de observación y de políticas, en estado **desarrollo** {{ev:EV-EC-03}}. No es un cortafuegos operativo y no se debe usar como protección.

## Un ejemplo cotidiano

Es como un portero con una lista de invitados que comprueba el DNI y no la palabra del visitante. El portero ya sabe leer DNIs y aplicar la lista, pero todavía no tiene llave para cerrar la puerta: si la lista dice "no pasa", solo puede anotar "no tengo llave".

## Diagrama

{{diagram:firewall-decision}}

## Paso a paso

1. Entra un flujo de red observado (hoy, de entrada sintética o de prueba: nunca se capturó un paquete real {{ev:EV-EC-64}}).
2. Un resolutor de firma averigua la firma de código real del proceso.
3. El motor de políticas evalúa las reglas: coincide, no coincide o **indeterminado** si falta evidencia.
4. Un paso de aplicación convierte la decisión en acción. Sin un permiso utilizable, una decisión de bloqueo acaba como "acción no disponible: falta el permiso" {{ev:EV-EC-60}}.
5. Se crea un evento de auditoría y se guarda en una cola local; su envío a MacCoreGuard solo se ha probado contra un doble de prueba {{ev:EV-EC-04}}.

## Cómo funciona por dentro

Arquitectura por capas {{ev:EV-EC-63}}:

| Capa | Función |
|---|---|
| Lógica de dominio | Lógica pura: flujos, políticas, DNS, correlación, red, eventos de auditoría y una cola local |
| Adaptadores de plataforma | Única capa que habla con marcos de Apple |
| Interfaz | Una app SwiftUI (usa la biblioteca compartida MacGuardDesignKit) y una herramienta de línea de comandos de solo lectura |

Algoritmos con código que los prueba (problema, evidencia):

- **Evaluación de políticas**: decide con tres valores (coincide / no coincide / indeterminado). Evita tratar "sin datos" como "permitido".
- **Resolución de firma**: resuelve la identidad de firma desde un audit token, un pid o una ruta. No está pensada para detectar inyección de código: eso se asigna a MacProcessGuard, que es solo un concepto.
- **Lectores de DNS, TLS y QUIC**: leen DNS, el nombre de servidor de TLS y paquetes iniciales de QUIC. Solo se han probado con bytes de prueba.
- **Reglas de integridad de red**: detectan cambios de VPN, rutas o DNS; solo modos observar y alertar.
- **Sensor de captura de paquetes** opcional: en la máquina de desarrollo el acceso se denegó por permisos {{ev:EV-EC-64}}.

### Canal hacia MacCoreGuard

La documentación de arquitectura describe un canal autenticado como diseño objetivo del lado de MacCore. **El cliente usa un canal local más simple que el diseño objetivo; las fuentes de producción no contienen la implementación objetivo** {{ev:EV-EC-61}}. El cliente y sus comprobaciones se ejercitan solo contra un doble de prueba.

## Cómo comprobarlo tú

El repositorio es privado, así que no hay comandos públicos que ejecutar. No se ejecutó nada para escribir esta página: los datos son una lectura estática del proyecto.

## Pruebas: qué cifras hay y de dónde salen

La cifra de pruebas del README está **desactualizada** {{ev:EV-EC-62}}. Los documentos del propio proyecto dan cifras de cientos hasta algo más de mil comprobaciones deterministas a lo largo de sucesivas fases, ninguna re-medida para esta revisión, y una suite independiente del módulo de integridad de red que pasa entera según su propio informe.

Pendiente según su propio cierre: ninguna captura real de paquetes, ni ejecución con el sanitizador de hilos, ni fuzzing guiado por cobertura, ni pruebas de rendimiento {{ev:EV-EC-64}}. El README también afirma que no hay dependencias externas, ya falso (usa MacGuardDesignKit).

## Límites

- No bloquea ni observa tráfico real hoy {{ev:EV-EC-60}}.
- No hay compilación firmada ni notarizada, y el propio proyecto no se declara listo para producción {{ev:EV-EC-65}}.
- Coexistir con otros filtros de contenido ya instalados es un bloqueo documentado sin resolver.
- No sustituye a MacProcessGuard (identidad de proceso) ni a MacCoreGuard (registro verificable): ninguno existe como servicio {{ev:EV-EC-05}}.

## Estado

| Capacidad | Estado |
|---|---|
| Motor de políticas, modelo de flujos, resolución de firma, app SwiftUI, línea de comandos | Implementado, no desplegado |
| Cliente MacCoreGuard (canal local simple) | Implementado, probado solo contra un doble de prueba |
| Observación y bloqueo reales (extensión del sistema) | Planificado, sin permiso confirmado como utilizable |
| Endpoint Security, captura de paquetes, Rust | Planificado o fuera de este repositorio; sin código |

Las fases iniciales de base e interfaz están cerradas; una fase posterior está parcial; el módulo de integridad de red está integrado {{ev:EV-EC-04}}. Sin fechas. Más: [Network Extension](ES-Tech-NetworkExtension), [Firma de código](ES-Tech-CodeSigning).
