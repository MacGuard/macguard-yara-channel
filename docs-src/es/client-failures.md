---
title: Fallos y recuperación
summary: Qué hace la app cuando algo falla: firma, red, fichero alterado, retroceso o corte durante la instalación.
---
En todos los casos el resultado es el mismo: no se instala nada nuevo, las reglas ya instaladas siguen funcionando y se explica el motivo a la persona con el detalle técnico.

## Fallo de firma

{{diagram:client-signature-failure}}

## Fallo de red

{{diagram:client-network-failure}}

## Fichero alterado

{{diagram:client-altered-file}}

## Retroceso o bifurcación

{{diagram:client-rollback}}

El estado de confianza (el checkpoint verificado más reciente) se guarda en un fichero con permisos 0600 y se escribe antes de activar las reglas, así que un corte no lo deja atrás.

## Corte durante la instalación

Ver el diagrama de [Instalación atómica](page:client-update). Un diario permite al siguiente arranque terminar o deshacer la sustitución, y un bloqueo de fichero impide dos actualizaciones a la vez.
