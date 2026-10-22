# Ecosistema MacGuard

[Inicio](ES-Home) · [Roadmap global](ES-Roadmap)

## En 30 segundos

Imagina la seguridad de una casa: una puerta con cerradura, una ventana con alarma, un portero que mira quién entra. Ninguna cosa sola basta. MacGuard sigue la misma idea: **varias capas pequeñas e independientes**, cada una con una tarea concreta y con límites claros. Ninguna promete detenerlo todo.

## Las capas

{{diagram:protection-layers}}

Cada capa cubre un punto distinto del camino que sigue algo hasta ejecutarse en tu Mac. Si una capa falla o aún no existe, las demás **no la sustituyen**.

## Cómo se relacionan las aplicaciones

- **YARA Channel** suministra reglas firmadas. **Installer Auditor** es el consumidor que hoy tiene evidencia: solo instala reglas que pasan todas las comprobaciones de firma, huella (hash) y registro de transparencia {{ev:EV-YC-09}}.
- **MacFirewallGuard** está diseñado para recibir de **MacProcessGuard** la identidad de cada proceso, pero MacProcessGuard todavía es solo un concepto, de modo que esa pieza falta {{ev:EV-EC-05}}.
- **MacFirewallGuard** tiene un cliente para **MacCoreGuard**, probado solo contra un doble de prueba (mock), porque MacCoreGuard es todavía un prototipo {{ev:EV-EC-04}} {{ev:EV-EC-06}}.
- **MacGuardDesignKit** reúne piezas de interfaz pensadas para compartirse. La evidencia revisada no muestra todavía otros proyectos que dependan de ella {{ev:EV-EC-07}}.
- **MacUSBGuard** funciona por su cuenta; no hay en la evidencia revisada dependencia con las otras aplicaciones {{ev:EV-EC-01}}.

## Qué puede y qué no puede hacer cada capa

| Capa | Ayuda a... | No garantiza... |
|---|---|---|
| Suministro (YARA Channel) | Saber que las reglas son las publicadas y no se han alterado | Que las reglas detecten todo, ni que sean inocuas: las escriben terceros {{ev:EV-YC-01}} |
| Instaladores (Installer Auditor) | Revisar un archivo con reglas verificadas | Que un archivo sin coincidencias sea seguro. Una regla solo reconoce lo que ya conoce |
| Dispositivos (MacUSBGuard) | Observar qué se conecta | Bloquear: sus pruebas de hardware dependen de un permiso de Apple que falta {{ev:EV-EC-02}} |
| Red (MacFirewallGuard) | Observar y modelar conexiones | Bloquear conexiones: hoy no puede {{ev:EV-EC-03}} |
| Procesos (MacProcessGuard) | Nada todavía: es un concepto | Nada: no existe {{ev:EV-EC-05}} |

## Lo que todavía no sabemos

- Cuándo estará lista cada aplicación: no hay fechas respaldadas.
- Cómo se comportará el conjunto en un Mac real con todas las capas: no existe una prueba de extremo a extremo entre aplicaciones {{ev:EV-YC-10}}.

Para el detalle por aplicación y el estado actual, ve al [Roadmap global](ES-Roadmap).
