# MacCoreGuard

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [Roadmap global](ES-Roadmap) · [MacUSBGuard](ES-App-USB)

## En 30 segundos

MacCoreGuard aspira a ser el libro de actas compartido de las aplicaciones MacGuard, donde cualquier cambio en lo escrito se notaría {{ev:EV-EC-27}}. Hoy es un prototipo: existen los formatos de datos y las matemáticas de hash (huellas digitales de datos). No hay ningún servicio en marcha ni ninguna aplicación lo usa todavía {{ev:EV-EC-28}}.

## Un ejemplo cotidiano

Piensa en un cuaderno donde cada página lleva la "huella" de la página anterior (la cadena de hashes). Si alguien arranca o altera una hoja, las huellas siguientes dejan de coincidir. Un resumen de todo el cuaderno (el árbol de Merkle) permite además demostrar que una página concreta estaba en él, sin enseñar el cuaderno entero. La analogía describe las matemáticas, no un cuaderno que ya funcione.

## Diagrama

{{diagram:maccore-chain-merkle}}

## Paso a paso (diseño)

1. Un productor (una de las aplicaciones MacGuard) propone un evento de seguridad, por ejemplo "se bloqueó un dispositivo USB". Solo MacCoreGuard decide registrarlo.
2. MacCore lo serializa en una forma canónica, de modo que el hash sea idéntico en cualquier Mac.
3. MacCore, y solo MacCore, asigna al registro su lugar en la secuencia y calcula el eslabón de la cadena.
4. Periódicamente se calcula la raíz del árbol de Merkle y se firmaría un punto de control.
5. Un verificador independiente, que no se fía del proceso escritor, comprobaría cadena, pruebas y firma.

**No implementado**: la recepción del paso 1, la secuenciación del paso 3, la firma del paso 4 y el paso 5. **Implementado**: la forma canónica (2), el cálculo del eslabón (3) y la raíz y las pruebas (4) {{ev:EV-EC-28}}.

## Cómo funciona por dentro

**Cadena de hashes.** Problema: detectar que un registro intermedio se alteró o se borró. Entrada: el evento canónico y el eslabón anterior. Cálculo: una cadena de hashes que enlaza cada registro con el anterior. Salida: un eslabón por registro. Detecta cambios en cualquier eslabón anterior; la protección frente a una reescritura completa de la cadena es un refuerzo planificado (firma y un testigo externo) y no está implementada. Coste: constante por registro. {{ev:EV-EC-27}}

**Árbol de Merkle según [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162).** Problema: resumir miles de registros en un solo hash y poder probar cosas sobre él. Entrada: los hashes de los registros. Salida: un único hash raíz. El árbol sigue la construcción pública de la RFC 9162; es el mismo tipo de árbol que usa Certificate Transparency.

- **Prueba de inclusión**: demuestra que un registro dado está en un árbol de un tamaño dado con un camino corto de hashes hermanos.
- **Prueba de consistencia**: demuestra que un árbol antiguo es prefijo del nuevo (solo se añadieron entradas, nada se reescribió).

Qué detecta: un registro que no está en el árbol, o un árbol reescrito en lugar de ampliado. Qué no impide: nada fuera de los datos registrados. Coste: recalcular la raíz es lineal en el número de registros por cada punto de control, aceptable porque no se hace por evento. {{ev:EV-EC-27}}

**Qué es un marcador de posición.** El registro persistente, la firma, la recepción y la verificación siguen sin implementar; no existe ningún servicio operativo {{ev:EV-EC-28}}. La firma, la gestión de claves, las escrituras a prueba de caídas y un cliente testigo aparecen solo en notas de diseño, sin código.

## Pruebas

Un arnés de pruebas propio con vectores de respuesta conocida, incluidas pruebas de inclusión para árboles pequeños, derivados según el código de una implementación de referencia escrita por separado. La documentación interna informa de pruebas de protocolo y criptografía; **no se han ejecutado de forma independiente para esta revisión**. No es posible probar las partes que son marcadores de posición {{ev:EV-EC-29}}.

## Cómo comprobarlo tú

El repositorio es privado; no se ejecutó nada para esta página. Para validar el algoritmo sin el repositorio, lee la sección del árbol de Merkle de la [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162).

## Límites

- Sin servicio, sin almacenamiento duradero, sin firma y sin verificador sin conexión.
- Se revisó un prototipo sin publicar; no se verificó nada más allá de él.
- MacFirewallGuard tiene un cliente de MacCoreGuard probado solo contra un doble de prueba; MacUSBGuard no lo importa {{ev:EV-EC-04}}. La biblioteca de diseño compartida no depende de él.

## Estado

El código y el paquete usan el nombre corto **MacCore**. Es un **prototipo sin publicar**: lo revisado es una implementación inicial que su propia documentación no presenta como autoritativa. Hoy existen los **formatos de datos** y las **matemáticas de hash**; el libro en disco, la firma, la recepción y el verificador son **marcadores de posición** {{ev:EV-EC-28}} {{ev:EV-EC-06}}. Todavía no garantiza nada a ningún usuario.

| Capacidad | Estado |
|---|---|
| Formato de evento e identificadores | Implementado, no desplegado |
| Cadena de hashes y árbol de Merkle con pruebas | Implementado con vectores de prueba, no desplegado |
| Libro duradero, firma, recepción, testigo, verificador | Planificado (marcadores de posición) |

El trabajo posterior está planificado, condicionado a compilar y pasar sus pruebas; sin fechas {{ev:EV-EC-06}}.

## Dónde seguir

[MacUSBGuard](ES-App-USB) · [Roadmap global](ES-Roadmap) · [Matriz de evidencias](ES-Evidence)
