# DriverKit

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [MacUSBGuard](ES-App-USB) · [Endpoint Security](ES-Tech-EndpointSecurity)

## En 30 segundos

DriverKit es la tecnología de Apple para escribir **controladores de hardware que funcionan fuera del núcleo del sistema**, como programas aparte. Si un controlador falla, no derriba todo el Mac. Es como una oficina de atención con su propia puerta: trabaja con el dispositivo, pero sin entrar en la sala de máquinas. Apple la documenta como framework {{ev:EV-EC-36}}; los controladores necesitan permisos específicos de Apple (el proyecto Karabiner lo documenta en su README) {{ev:EV-EC-34}}.

## En este proyecto: planeado y solo en ramas

**MacUSBGuard no usa DriverKit en su código actual.** Su README dice que DriverKit "no forma parte de este producto" porque, según Apple DTS, no se aprobaría un permiso USB que abarque todos los dispositivos con este fin; el código lo registra como permiso "deliberadamente no solicitado" y una prueba lo comprueba {{ev:EV-EC-22}}.

Aun así, existen **ramas separadas** (`ai/dk2-driverkit-v1` y derivadas: DK2.2-B, C1, C2) con archivos de controlador (`Driver/MacUSBGuardDriver.iig`, `.cpp`, un cliente de usuario estrecho) y pruebas de contrato. Su documentación las describe como hitos congelados cuya verificación con el permiso real de Apple "sigue siendo externa". En la rama actual (`ai/v1-release-integration`, 78f7d37) no hay ningún símbolo de DriverKit en `Sources`; solo comentarios, el permiso registrado y pruebas.

| Pregunta | Respuesta verificada |
|---|---|
| ¿Está en el producto actual? | No |
| ¿Existe código? | Sí, solo en ramas |
| ¿Funciona en un Mac real con permiso de Apple? | No verificado |
| ¿Es una defensa desplegada? | No: es solo una opción explorada |

## Límites

- Un controlador no es un cortafuegos ni un antivirus: solo mira dispositivos.
- Su aprobación por Apple no depende del código, y está sin resolver para este uso.
- Puede haber ramas más recientes que no revisé; me limité a las ramas locales listadas.

## Quién más lo usa

- **Karabiner-DriverKit-VirtualHIDDevice** (proyecto abierto de pqrs-org) implementa un teclado y un ratón virtuales con DriverKit, y su README indica que hay que solicitar permisos a Apple, con aprobación que puede tardar. Clasificación: usa la misma tecnología {{ev:EV-EC-34}}.

No incluyo más ejemplos porque no pude abrir otra fuente oficial. Nada de esto implica que esos proyectos usen MacGuard.

## Estado en este proyecto

| Capacidad | Estado |
|---|---|
| Controlador DriverKit para USB | Planeado / solo en ramas, fuera del producto |
| Dependencia de DriverKit en el producto actual | Ninguna |

## Dónde seguir

[MacUSBGuard](ES-App-USB) · [Endpoint Security](ES-Tech-EndpointSecurity) · [Matriz de evidencias](ES-Evidence)
