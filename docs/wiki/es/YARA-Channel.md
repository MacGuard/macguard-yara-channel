# MacGuard YARA Channel

[Inicio](ES-Home) · [Fuentes](ES-YARA-Sources) · [Validación](ES-YARA-Validation) · [Rendimiento](ES-YARA-Performance) · [Cuarentena](ES-YARA-Quarantine) · [Publicación](ES-YARA-Publishing) · [Transparencia](ES-YARA-Transparency) · [Verificar](ES-YARA-Verify) · [Archivo](ES-YARA-Archive) · [Límites](ES-YARA-Limits)

## En 30 segundos

MacGuard YARA Channel es un sistema que recopila, valida, prepara y distribuye reglas YARA verificables para ayudar a identificar patrones sospechosos en archivos.

Cada día, un proceso automático descarga reglas de dos repositorios públicos, las revisa con comprobaciones estáticas y con medidas reales del motor YARA, aparta las que no pasan y solo publica las que sí. Un conjunto que cambia se publica únicamente si la validación pasa y el trabajo de medición en macOS termina bien. Cualquiera puede comprobar la firma del resultado. Ayuda a reconocer patrones conocidos; **no** garantiza que un archivo sea seguro ni que una amenaza nueva se detecte. {{ev:EV-YC-20}}

## Qué es YARA, sin tecnicismos

Imagina que buscas en una biblioteca todos los libros que mencionan la frase «tesoro enterrado». Una regla YARA es esa instrucción escrita para un ordenador: «busca estas palabras o estos trozos de bytes dentro de un archivo, y avísame si se cumple esta condición». YARA no «entiende» el archivo: solo comprueba si aparecen ciertos patrones. Por eso sirve para señalar cosas que ya se conocen y por eso también puede equivocarse.

## Qué es una regla YARA

Una regla tiene un nombre, una sección `strings` (los patrones que se buscan: texto, bytes o expresiones regulares) y una `condition` (cuándo se considera que la regla «salta»). Ejemplo inventado para esta wiki; no detecta nada real:

```yara
// EJEMPLO inventado para esta wiki. No detecta ningún programa real.
rule Ejemplo_Marcador_Inofensivo
{
    strings:
        $marca = "HOLA-MACGUARD-EJEMPLO"
    condition:
        $marca
}
```

La regla salta solo si el archivo contiene exactamente ese texto. Las reglas reales combinan muchos patrones y condiciones (`any of them`, tamaño del archivo, módulos como `pe` para ejecutables de Windows).

## Un ejemplo cotidiano

Es como la lista de comprobación de un guardia de aduanas: «si en la maleta hay A y B, mira con más atención». La lista la escriben otras personas; el canal comprueba que esté bien escrita, que no tarde una eternidad en aplicarse y que no marque maletas inocentes, y entrega solo las listas que superan esas pruebas. No puede saber qué hay en maletas de un tipo que nadie ha descrito todavía.

## El viaje de una regla

{{diagram:architecture}}

## Paso a paso

| Paso | Qué ocurre | Página |
|---|---|---|
| 1. Recoger | Se descargan las reglas de dos repositorios públicos fijando el commit de cada ejecución | [Fuentes](ES-YARA-Sources) |
| 2. Validar | Comprobación estática, compilación y medidas del motor; se decide qué entra | [Validación](ES-YARA-Validation) |
| 3. Medir coste | Se mide CPU, memoria y latencia frente a la versión anterior | [Rendimiento](ES-YARA-Performance) |
| 4. Apartar | Lo que no pasa va a una cuarentena privada para revisión humana | [Cuarentena](ES-YARA-Quarantine) |
| 5. Publicar | Hashes, raíz Merkle, firma Sigstore y release | [Publicación](ES-YARA-Publishing) |
| 6. Registrar | Registro de transparencia con solo recuentos | [Transparencia](ES-YARA-Transparency) |
| 7. Verificar | Cómo comprueba un tercero firma, hashes y registro | [Verificar](ES-YARA-Verify) |
| 8. Conservar | Archivo histórico en varios proveedores (no operativo aún) | [Archivo](ES-YARA-Archive) |
| 9. Conocer los límites | Qué no hace el canal | [Límites](ES-YARA-Limits) |

## Cómo funciona por dentro

El orden real de los programas, según `.github/workflows/daily.yml`: `scripts/prepare.py` (recoge), `scripts/rulecheck.py` (clasificación estática), `scripts/dynamic_gate.py` con `scripts/bench.py` (medidas con el motor), `scripts/decide.py` (puerta de decisión) y, si el conjunto cambia, un trabajo de medición en `macos-15`. Solo si ese trabajo termina bien, `daily.yml` pide `publish.yml`, que vuelve a verificar, firma y publica. La puerta es el único punto que decide qué conjunto es publicable. {{ev:EV-YC-20}} {{ev:EV-YC-89}}

- Qué detecta: coincidencias con patrones que alguien escribió en una regla.
- Qué **no** previene: malware sin regla, ofuscado, o cuyo patrón no esté en las reglas; ni garantiza ausencia de falsos positivos.
- Evidencia de implementación: los archivos citados arriba; diagrama `docs-src/diagrams/architecture.mmd`.

## Cómo comprobarlo tú

- Suite de pruebas del repositorio: `python3 -m unittest discover -s tests` (requiere `yara` instalado).
- Fuente de la lista de fuentes: [config/sources.json](https://github.com/MacGuard/macguard-yara-channel/blob/main/config/sources.json); política: [config/policy.json](https://github.com/MacGuard/macguard-yara-channel/blob/main/config/policy.json).
- Flujo diario: [daily.yml](https://github.com/MacGuard/macguard-yara-channel/blob/main/.github/workflows/daily.yml).

## Límites

Un conjunto de reglas validado no equivale a un archivo seguro. Lo que el canal no cubre está en [Límites](ES-YARA-Limits). No existe prueba de rendimiento de extremo a extremo con Installer Auditor ({{ev:EV-YC-10}}).

## Estado

| Capacidad | Estado |
|---|---|
| Revisión diaria, puerta de decisión y release firmada | publicado {{ev:EV-YC-02}} {{ev:EV-YC-03}} |
| Panel privado de cuarentena | operativo {{ev:EV-YC-05}} |
| Retiradas persistentes, políticas, anclas y control de admisión de fuentes | implementado en el repositorio, aún no activo en producción {{ev:EV-YC-06}} {{ev:EV-YC-07}} |
| Archivo en tres proveedores | no operativo {{ev:EV-YC-08}} |
| Prueba de rendimiento con la app real | planificado {{ev:EV-YC-10}} |
