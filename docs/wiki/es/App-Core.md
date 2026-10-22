# MacCoreGuard

[Inicio](ES-Home) · [Ecosistema](ES-Ecosystem) · [Roadmap global](ES-Roadmap) · [MacUSBGuard](ES-App-USB)

## En 30 segundos

MacCoreGuard (el código y el paquete se llaman **MacCore**; solo el nombre del repositorio privado usa "maccore-guard") quiere ser el "cuaderno de actas" común de las aplicaciones MacGuard: cada una propone eventos de seguridad ("se bloqueó un USB") y solo MacCoreGuard decide anotarlos de forma permanente y a prueba de manipulaciones {{ev:EV-EC-27}}.

**Estado: prototipo de un solo commit** (b0b0f07, 2026-10-09) en una rama de candidato que su propio mensaje declara "no autoritativa" y no publicada. Hoy existen el **formato de los datos** y las **matemáticas de hashes**; el registro en disco, la firma, la ingesta y el verificador son **marcadores de posición** {{ev:EV-EC-28}} {{ev:EV-EC-06}}.

No garantiza todavía nada para un usuario: no hay servicio en marcha, y ninguna aplicación lo importa hoy.

## Un ejemplo cotidiano

Piensa en un cuaderno donde cada página lleva escrita la "huella" de la página anterior: si alguien arranca una hoja o la cambia, las huellas siguientes dejan de cuadrar. Además, un resumen del cuaderno entero permite demostrar que una página concreta estaba dentro, sin enseñar todo el cuaderno. Esta analogía describe la matemática, no un cuaderno que ya esté funcionando.

## Diagrama

{{diagram:maccore-chain-merkle}}

## Paso a paso (diseño)

1. Un productor (un conjunto cerrado de aplicaciones MacGuard; no puede declararse a sí mismo) propone un evento.
2. MacCore lo serializa en JSON canónico (claves ordenadas, sin números en coma flotante, para que el hash sea idéntico en cualquier Mac).
3. MacCore, y solo él, asigna un número de secuencia sin huecos desde 0 y calcula el eslabón de la cadena.
4. Cada cierto tiempo se calcula la raíz del árbol de Merkle y se firmaría un punto de control.
5. Un verificador independiente, sin confiar en el proceso escritor, comprobaría cadena, pruebas y firma.

**No están implementados**: la recepción del paso 1, la numeración del paso 3, la firma del paso 4 y el paso 5. Sí lo están: la lista cerrada de productores (paso 1), el JSON canónico (2), la fórmula del eslabón (3) y la raíz y las pruebas (4) {{ev:EV-EC-28}}.

## Cómo funciona por dentro

**Cadena de hashes.** Problema: detectar que se alteró o borró un registro intermedio. Entrada: hash anterior, número de secuencia y bytes canónicos del evento. Cálculo: `recordHash = SHA-256(0x02 || hashAnterior || secuencia big-endian de 64 bits || bytesDelEvento)`. Salida: 32 bytes. Detecta cambios en cualquier eslabón previo; **no** evita que quien controle todo el almacenamiento reescriba la cadena entera desde el principio: para eso sirven la firma y un testigo externo, aún no implementados. Código: `CanonicalHashing.recordHash`, `Sources/MacCoreCrypto/CanonicalHashing.swift` {{ev:EV-EC-27}}.

**Árbol de Merkle RFC 9162.** Problema: resumir miles de registros en un solo hash y demostrar cosas sobre él. Entrada: hashes de hojas. Cálculo (RFC 9162, apartado 2.1): hoja = `SHA-256(0x00 || datos)`, nodo = `SHA-256(0x01 || izquierda || derecha)`, partiendo en la mayor potencia de dos menor que n; el árbol vacío vale el SHA-256 de la cadena vacía. Los prefijos `0x00`, `0x01` y `0x02` separan dominios para que un hash de hoja, de nodo o de registro nunca se confundan. Es el mismo tipo de árbol de Certificate Transparency.

- **Prueba de inclusión** (`inclusionProof` / `verifyInclusionProof`): demuestra que la hoja número *m* está en un árbol de tamaño *n* con una ruta de hashes hermanos.
- **Prueba de consistencia** (`consistencyProof` / `verifyConsistencyProof`): demuestra que un árbol viejo es prefijo del nuevo (solo se añadió, nada se reescribió).

Coste declarado en el propio código: recalcular la raíz es O(n) por punto de control, aceptable porque no se hace por evento. Código: `Sources/MacCoreCrypto/MerkleTree.swift` {{ev:EV-EC-27}}.

**Qué es marcador.** `MacCoreLedger`, `MacCoreSigning`, `MacCoreIngest` y `MacCoreWitness` contienen un archivo de una línea; `maccorectl` solo imprime "not yet implemented" {{ev:EV-EC-28}}. Firmas P-256, claves en Secure Enclave o llavero, rotación de claves, escritura atómica con recuperación de fallos y cliente testigo están descritos solo en el contrato de diseño o en comentarios, sin código.

## Pruebas

Arnés propio `maccore-tests` (ejecutable, tres archivos), con vectores de respuesta conocida (KAT), entre ellos pruebas de inclusión para árboles de 1 a 6 hojas, derivados según el código de una referencia escrita aparte en Python/hashlib. El mensaje del commit declara "147/147 tests" para Protocolo y Cripto: autoinformado, **no ejecutado por mí**. No hay pruebas posibles para las partes marcador {{ev:EV-EC-29}}.

## Cómo comprobarlo tú

El repositorio es privado. Su README indica `swift build` y `swift run maccore-tests` como puerta de cada oleada; no se ejecutaron aquí. Para validar el algoritmo sin el repositorio puedes leer el apartado 2.1 del RFC 9162.

## Límites

- No hay servicio, ni almacenamiento durable, ni firma, ni verificador sin conexión.
- Una sola rama de candidato, sin tags, y con reparto de responsabilidades entre partes sin resolver según el commit; no he verificado si existe otra implementación en otra rama o equipo.
- MacFirewallGuard tiene un cliente de MacCoreGuard probado solo contra un simulacro; MacUSBGuard no lo importa {{ev:EV-EC-04}}. MacGuardDesignKit tiene prohibido depender de él.

## Estado

| Capacidad | Estado |
|---|---|
| Formato de eventos y identificadores | Implementado, no desplegado |
| Cadena de hashes y árbol Merkle con pruebas | Implementado con vectores de prueba, no desplegado |
| Registro durable, firma, ingesta, testigo, verificador | Planeado (marcadores de posición) |

Oleadas de trabajo nombradas TL-0 a TL-8, cada una condicionada a compilar y pasar sus pruebas; no hay fechas {{ev:EV-EC-06}}.

## Dónde seguir

[MacUSBGuard](ES-App-USB) · [Roadmap global](ES-Roadmap) · [Matriz de evidencias](ES-Evidence)
