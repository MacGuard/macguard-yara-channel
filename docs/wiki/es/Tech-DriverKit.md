# DriverKit

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [MacUSBGuard](ES-App-USB) · [Endpoint Security](ES-Tech-EndpointSecurity)

## En 30 segundos

DriverKit es la tecnología de Apple para escribir **controladores de hardware que funcionan fuera del núcleo del sistema**, como programas aparte. Si un controlador falla, no derriba todo el Mac. Es como una oficina de atención con su propia puerta: trabaja con el dispositivo, pero sin entrar en la sala de máquinas. Apple la documenta como framework {{ev:EV-EC-36}}; los controladores necesitan permisos específicos de Apple (el proyecto Karabiner lo documenta en su README) {{ev:EV-EC-34}}.

## En este proyecto: planificado y fuera del producto

**MacUSBGuard no usa DriverKit en su código actual.** Su documentación dice que DriverKit "no forma parte de este producto"; según la documentación del proyecto, ese permiso no se solicita, y el código lo registra como deliberadamente no solicitado, algo que una prueba comprueba {{ev:EV-EC-22}}.

Aun así, existe código de controlador solo en líneas de desarrollo no publicadas, fuera del producto, con pruebas de contrato. Su documentación las describe como hitos congelados; la verificación con el permiso de Apple está pendiente. En la línea de integración actual no hay código de DriverKit en las fuentes de la aplicación; solo comentarios, la decisión registrada sobre el permiso y pruebas.

| Pregunta | Respuesta verificada |
|---|---|
| ¿Está en el producto actual? | No |
| ¿Existe código? | Sí, solo en líneas de desarrollo no publicadas |
| ¿Funciona en un Mac real con permiso de Apple? | No verificado |
| ¿Es una defensa desplegada? | No: es solo una opción explorada |

## Límites

- Un controlador no es un cortafuegos ni un antivirus: solo mira dispositivos.
- Su aprobación por Apple no depende del código, y está sin resolver para este uso.
- Puede haber líneas de desarrollo más recientes que esta revisión no examinó.

## Quién más lo usa

- **Karabiner-DriverKit-VirtualHIDDevice** (proyecto abierto de pqrs-org) implementa un teclado y un ratón virtuales con DriverKit, y su README indica que hay que solicitar permisos a Apple, con aprobación que puede tardar. Clasificación: usa la misma tecnología {{ev:EV-EC-34}}.

No se incluyen más ejemplos porque no se pudo abrir otra fuente oficial. Nada de esto implica que esos proyectos usen MacGuard.

## Estado en este proyecto

| Capacidad | Estado |
|---|---|
| Controlador DriverKit para USB | Planificado, solo en líneas de desarrollo no publicadas, fuera del producto |
| Dependencia de DriverKit en el producto actual | Ninguna |

## Dónde seguir

[MacUSBGuard](ES-App-USB) · [Endpoint Security](ES-Tech-EndpointSecurity) · [Matriz de evidencias](ES-Evidence)
