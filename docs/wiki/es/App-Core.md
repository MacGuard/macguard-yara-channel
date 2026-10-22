# MacCoreGuard

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [Roadmap global](ES-Roadmap) · [MacUSBGuard](ES-App-USB)

## En 30 segundos

MacCoreGuard aspira a ser el libro de actas compartido de las aplicaciones MacGuard, donde cualquier cambio en lo escrito se notaría {{ev:EV-EC-27}}. Hoy es un prototipo: existen los formatos de datos y las matemáticas de hash (huellas digitales de datos). No hay ningún servicio en marcha ni ninguna aplicación lo usa todavía {{ev:EV-EC-28}}.

## Un ejemplo cotidiano

Piensa en un cuaderno donde cada página lleva la "huella" de la página anterior (la cadena de hashes). Si alguien arranca o altera una hoja, las huellas siguientes dejan de coincidir. Un resumen de todo el cuaderno (el árbol de Merkle) permite además demostrar que una página concreta estaba en él, sin enseñar el cuaderno entero. La analogía describe las matemáticas, no un cuaderno que ya funcione.

## Diagrama

{{diagram:maccore-chain-merkle}}

## Paso a paso (diseño)

1. Un productor (un conjunto cerrado de aplicaciones MacGuard; no puede declararse a sí mismo) propone un evento de seguridad, por ejemplo "se bloqueó un dispositivo USB". Solo MacCoreGuard decide registrarlo.
2. MacCore lo serializa en una forma canónica, de modo que el hash sea idéntico en cualquier Mac.
3. MacCore, y solo MacCore, asigna un número de secuencia sin huecos y calcula el eslabón de la cadena.
4. Periódicamente se calcula la raíz del árbol de Merkle y se firmaría un punto de control.
5. Un verificador independiente, que no se fía del proceso escritor, comprobaría cadena, pruebas y firma.

**No implementado**: la recepción del paso 1, la numeración del paso 3, la firma del paso 4 y el paso 5. **Implementado**: la lista cerrada de productores (paso 1), la forma canónica (2), el cálculo del eslabón (3) y la raíz y las pruebas (4) {{ev:EV-EC-28}}.

## Cómo funciona por dentro

**Cadena de hashes.** Problema: detectar que un registro intermedio se alteró o se borró. Entrada: el hash anterior, el número de secuencia y el evento canónico. Cálculo: un hash SHA-256 con separación de dominios, de modo que el hash de un registro nunca se confunda con otro tipo de hash. Salida: un hash de 32 bytes por registro. Detecta cambios en cualquier eslabón anterior; **no** impide que quien controla todo el almacenamiento reescriba la cadena entera desde el principio: eso lo abordan la firma y un testigo externo, y ninguno está implementado. Coste: constante por registro. {{ev:EV-EC-27}}

**Árbol de Merkle según [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162).** Problema: resumir miles de registros en un solo hash y poder probar cosas sobre él. Entrada: los hashes de los registros. Salida: un único hash raíz. El árbol sigue la construcción pública de la RFC 9162, con separación de dominios entre hojas y nodos internos; es el mismo tipo de árbol que usa Certificate Transparency.

- **Prueba de inclusión**: demuestra que un registro dado está en un árbol de un tamaño dado con un camino corto de hashes hermanos.
- **Prueba de consistencia**: demuestra que un árbol antiguo es prefijo del nuevo (solo se añadieron entradas, nada se reescribió).

Qué detecta: un registro que no está en el árbol, o un árbol reescrito en lugar de ampliado. Qué no impide: nada fuera de los datos registrados. Coste: recalcular la raíz es lineal en el número de registros por cada punto de control, aceptable porque no se hace por evento. {{ev:EV-EC-27}}

**Qué es un marcador de posición.** El registro persistente, la firma, la recepción y la verificación siguen sin implementar; no existe ningún servicio operativo {{ev:EV-EC-28}}. Las firmas digitales, las claves respaldadas por hardware o por el llavero, la rotación de claves, las escrituras atómicas con recuperación ante caídas y un cliente testigo aparecen solo en el contrato de diseño o en comentarios, sin código.

## Pruebas

Un arnés de pruebas propio con vectores de respuesta conocida, incluidas pruebas de inclusión para árboles pequeños, derivados según el código de una implementación de referencia escrita por separado. La documentación interna informa de pruebas de protocolo y criptografía; **no se han ejecutado de forma independiente para esta revisión**. No es posible probar las partes que son marcadores de posición {{ev:EV-EC-29}}.

## Cómo comprobarlo tú

El repositorio es privado; no se ejecutó nada para esta página. Para validar el algoritmo sin el repositorio, lee la sección del árbol de Merkle de la [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162).

## Límites

- Sin servicio, sin almacenamiento duradero, sin firma y sin verificador sin conexión.
- Se revisó un prototipo sin publicar; no se ha verificado el estado de otras líneas de desarrollo.
- MacFirewallGuard tiene un cliente de MacCoreGuard probado solo contra un servidor simulado; MacUSBGuard no lo importa {{ev:EV-EC-04}}. La biblioteca de diseño compartida no depende de él.

## Estado

El código y el paquete usan el nombre corto **MacCore**. Es un **prototipo sin publicar**: lo revisado es una implementación inicial que su propia documentación no presenta como autoritativa. Hoy existen los **formatos de datos** y las **matemáticas de hash**; el libro en disco, la firma, la recepción y el verificador son **marcadores de posición** {{ev:EV-EC-28}} {{ev:EV-EC-06}}. Todavía no garantiza nada a ningún usuario.

| Capacidad | Estado |
|---|---|
| Formato de evento e identificadores | Implementado, no desplegado |
| Cadena de hashes y árbol de Merkle con pruebas | Implementado con vectores de prueba, no desplegado |
| Libro duradero, firma, recepción, testigo, verificador | Planificado (marcadores de posición) |

El trabajo está planificado en oleadas por etapas, cada una condicionada a compilar y pasar sus pruebas; sin fechas {{ev:EV-EC-06}}.

## Dónde seguir

[MacUSBGuard](ES-App-USB) · [Roadmap global](ES-Roadmap) · [Matriz de evidencias](ES-Evidence)
