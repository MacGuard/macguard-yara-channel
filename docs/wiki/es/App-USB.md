# MacUSBGuard

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [Roadmap global](ES-Roadmap) · [Endpoint Security](ES-Tech-EndpointSecurity) · [DriverKit](ES-Tech-DriverKit)

## En 30 segundos

MacUSBGuard es un programa para Mac pensado para decidir qué dispositivos USB pueden funcionar **mientras la pantalla está bloqueada**. Distingue cuatro familias: teclados y ratones (HID), memorias de almacenamiento, adaptadores de red USB y llaves de seguridad físicas como las YubiKey. Por diseño, un dispositivo nuevo empieza como "no confiable" y está diseñado para bloquearse del todo con el Mac bloqueado. Hoy el programa solo observa: no bloquea nada {{ev:EV-EC-20}}.

**Estado: en validación.** Hoy el programa se declara a sí mismo en modo **solo observación**, nunca "activo", porque el permiso de Apple que permite bloquear teclados y ratones no consta como utilizable {{ev:EV-EC-01}} {{ev:EV-EC-02}}. No es un control de seguridad listo para producción.

No puede garantizar: bloquear un teclado malicioso hoy en este equipo, bloquear adaptadores de red USB (solo los detecta), ni proteger contra un atacante con el Mac desbloqueado.

## Un ejemplo cotidiano

Es como el portero de un edificio con una lista de inquilinos: de noche (Mac bloqueado) está pensado para dejar pasar solo a quien está en la lista y solo a las salas que le corresponden. La analogía no dice que el portero ya tenga las llaves de todas las puertas: aquí le falta el permiso del administrador del edificio (Apple).

## Diagrama

{{diagram:usb-decision-flow-1-locked}}

{{diagram:usb-decision-flow-2-resolver}}

{{diagram:usb-decision-flow-3-deny}}

## Paso a paso

1. Conectas un dispositivo. El programa lo inventaría y calcula una huella SHA-256 de sus datos canónicos {{ev:EV-EC-23}}.
2. Si el Mac está desbloqueado, no interviene.
3. Si está bloqueado, se ha diseñado una decisión de **dos etapas**: primero sobre el dispositivo (no confiable implica denegar todo) y después sobre cada interfaz concedida; si la identidad cambia, se bloquea la readmisión.
4. La decisión se traduce en una respuesta de Endpoint Security (HID) o en una decisión de montaje (almacenamiento).
5. Un resolutor global combina el estado de cada dominio: no puede llegar a "fuerte" si un dominio requerido solo observa.

## Arquitectura

Paquete Swift para macOS 13 o superior, sin dependencias externas {{ev:EV-EC-26}}, organizado en capas:

- lógica de decisión que no hace llamadas al sistema;
- adaptadores de plataforma;
- una interfaz: una app, una herramienta de línea de comandos y un componente privilegiado, además de un arnés de pruebas interno.

Frontera de confianza: el componente privilegiado está separado de la interfaz y comprueba quién lo llama.

## Cómo funciona por dentro

| Pieza | Qué resuelve | Qué NO evita | Evidencia |
|---|---|---|---|
| Decisión de admisión en dos etapas | Decide dispositivo y luego interfaz con el Mac bloqueado | Un dispositivo ya confiable que se comporte mal | Ver la [matriz de evidencias](ES-Evidence) |
| Huella del dispositivo | Huella SHA-256 de una descripción canónica del dispositivo | Que un dispositivo imite todos los campos | Ver la [matriz de evidencias](ES-Evidence) |
| Motor de decisión de Endpoint Security | Convierte un evento de apertura de dispositivo en permitir/denegar con motivo; se niega a actuar sin identidad fiable | Nada en vivo: no hay permiso utilizable para ejecutarlo {{ev:EV-EC-21}} | Ver la [matriz de evidencias](ES-Evidence) |
| Resolutor de protección global | Estado global honesto por dominio | Falsos "verdes" por promedio | Ver la [matriz de evidencias](ES-Evidence) |
| Política de admisión de almacenamiento | Aprueba o rechaza montajes de almacenamiento | Que el sistema respete la decisión: sin probar | Ver la [matriz de evidencias](ES-Evidence) |
| Desafío de llave | Prueba criptográfica de una llave frente a mera huella | Robo físico de la llave y su PIN | Ver la [matriz de evidencias](ES-Evidence) |

El código usa servicios del sistema de Apple para dispositivos y discos, comunicación entre procesos, comprobación de firmas de código, tarjetas inteligentes y autenticación local {{ev:EV-EC-23}}. **Solo planeadas o descartadas:** DriverKit (opción explorada, fuera del producto, ver más abajo) y otros enfoques que se estudiaron y no se eligieron {{ev:EV-EC-22}}.

## Pruebas

Las cifras son autoinformadas y **no se han ejecutado para esta revisión**. Hay un solo arnés de pruebas propio con miles de comprobaciones (recuento estático; los bucles multiplican las ejecuciones reales) {{ev:EV-EC-25}}.

Existen dos conjuntos de cifras de pruebas autoinformadas y no son comparables; no se volvió a ejecutar nada {{ev:EV-EC-20}}. Cuál es "la" candidata a V1 no está resuelto en lo revisado. Pendientes documentados: pruebas de hardware HID y almacenamiento, validación con VoiceOver, auditoría visual y validación de instalación.

## Cómo comprobarlo tú

El código es privado: la comprobación corresponde al propietario. No se ejecutó nada para escribir esta página: los datos son una lectura estática del proyecto.

## Límites

- Con el Mac de pruebas, HID está en estado parcial: el permiso restringido de Endpoint Security no consta como utilizable {{ev:EV-EC-02}}.
- Red USB: solo detección.
- Hay un instalador beta local cuyas notas dicen que la comprobación de notarización pasó, pero es una nota propia: **no está verificada la notarización ni que se haya publicado** {{ev:EV-EC-24}}. Otro informe dice que no estaba notarizado. La documentación declara firma ad hoc.
- Ninguna otra aplicación MacGuard lo usa ni él usa otra: sin dependencias entre ellas {{ev:EV-EC-01}}.

## Estado

| Capacidad | Estado |
|---|---|
| Motor de política y resolutores | Implementado, probado por su propio arnés |
| Admisión de almacenamiento | Implementada; efecto real sin verificar |
| Bloqueo HID por Endpoint Security | El cliente compila; en vivo sin verificar (sin permiso confirmado como utilizable) |
| Bloqueo de red USB | No implementado |
| DriverKit | Opción explorada, no verificada, fuera del producto |
| Notarización / publicación del instalador | No verificadas |

Siguiente objetivo documentado: crear el candidato V1; el próximo frente de trabajo está sin elegir {{ev:EV-EC-01}}.

## Dónde seguir

[Endpoint Security](ES-Tech-EndpointSecurity) · [DriverKit](ES-Tech-DriverKit) · [Firma de código](ES-Tech-CodeSigning) · [MacCoreGuard](ES-App-Core) · [Matriz de evidencias](ES-Evidence)
