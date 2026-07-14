# Autorización de acceso a expedientes con Policy as Code

Implementación de referencia de una política de control de acceso escrita en
Rego (Open Policy Agent), con contrato de datos explícito, integración en Python
sin dependencias externas, 144 pruebas y CI reproducible.

**No es el sistema de ningún cliente ni de ninguna organización.** Es un
ejercicio propio, escrito para explorar cómo se diseña una política de
autorización que no falle en silencio. El identificador `RCI-EXP-001` es
ficticio.

---

## El problema

Un funcionario pide abrir un expediente. ¿Se le deja?

La respuesta ingenua es comprobar si su unidad coincide con la unidad asignada
al expediente. Pero esa comprobación esconde varias trampas que solo aparecen en
producción:

**El dato con el que decides puede estar caducado.** La asignación del
expediente la sirve otro sistema. Si esa fuente lleva horas sin actualizarse,
"la unidad coincide" es una afirmación sobre el pasado, no sobre el presente.
Decidir con un dato obsoleto es tan peligroso como decidir sin dato.

**Un input mal formado no puede tumbar el motor.** Si llega una fecha imposible
(`2026-02-31`), un campo con el tipo equivocado o un JSON que ni siquiera es un
objeto, la política no debe abortar: debe *denegar de forma estructurada* y
explicar por qué. Un motor que revienta es un motor que no deniega.

**Las excepciones son la puerta trasera de cualquier sistema de permisos.** Si
existe un mecanismo de excepción —y siempre acaba existiendo— hay que definir
con precisión qué es una excepción válida, y qué NO puede conceder por mucho que
lo diga.

Esta política responde a las tres.

---

## Decisiones de diseño

### 1. La frescura del dato es parte de la decisión

La política no confía en que la asignación esté al día: exige que el adaptador
le diga si el dato es `FRESH`, `STALE` o `UNAVAILABLE`, y **rechaza como input
inválido cualquier contradicción**. Si el estado declarado dice `FRESH` pero la
edad real del timestamp supera el umbral, eso no es una decisión de negocio: es
un adaptador roto, y se trata como tal.

Con un dato obsoleto no se deniega ni se permite: se **escala**. Denegar sería
castigar al usuario por un fallo de infraestructura; permitir sería decidir a
ciegas. La operación se retiene y pasa a revisión humana.

### 2. Un input inválido siempre produce una respuesta, nunca una excepción

El resultado está **siempre definido**, con cualquier entrada imaginable: `null`,
un array, un número, un objeto vacío. Las fechas se validan por forma, por
calendario y por representabilidad *antes* de parsearlas, de modo que
`time.parse_rfc3339_ns` nunca recibe algo que pueda hacerla abortar — ni siquiera
con `--strict-builtin-errors`.

Cuando el input no cumple el contrato, la salida es
`DENY / RCI_DENY_INVALID_INPUT` con la lista ordenada de errores concretos. El
llamante siempre sabe qué pasó.

### 3. La decisión y su justificación se emiten juntas o no se emiten

`decision`, `reason_code` y `execution_allowed` viven en un único objeto
`outcome`, construido en ramas mutuamente excluyentes. No pueden desincronizarse
entre reglas: es imposible que la política diga `DENY` con `execution_allowed:
true`, porque no hay ningún camino en el código que lo permita.

### 4. Una excepción nunca amplía los permisos base

La acción solicitada debe estar en `actor.acciones_permitidas` (lista ya resuelta
por el sistema corporativo) **antes** de mirar unidades o excepciones. Una
excepción puede saltarse la coincidencia de unidad; no puede conceder una acción
que el actor no tenía. Y una excepción que se apoya en una fuente obsoleta no
vale: las excepciones también caducan.

### 5. La política no calcula permisos, los comprueba

La frontera de confianza es explícita. Rego no consulta directorios ni recalcula
roles: recibe hechos ya resueltos por el sistema llamante y decide sobre ellos.
Lo que sí hace es **no fiarse** de que esos hechos sean coherentes entre sí.

---

## Las seis decisiones posibles

| Decisión | Código | ¿Se ejecuta? | Cuándo |
|---|---|---|---|
| `ALLOW` | `RCI_ALLOW_UNIT_MATCH` | Sí | Dato fresco y la unidad del actor coincide con la asignada |
| `ALLOW_WITH_EXCEPTION` | `RCI_ALLOW_EXCEPTION_APPLIED` | Sí (y se registra) | No coincide la unidad, pero hay una excepción vigente y con fuente fresca |
| `DENY` | `RCI_DENY_UNIT_MISMATCH` | No | Dato fresco, unidad distinta, sin excepción válida |
| `DENY` | `RCI_DENY_ACTION_NOT_ALLOWED` | No | La acción no está entre las permitidas al actor |
| `DENY` | `RCI_DENY_SOURCE_UNAVAILABLE` | No | La fuente de asignación no está disponible |
| `DENY` | `RCI_DENY_INVALID_INPUT` | No | El input no cumple el contrato (con `validation_errors` detallados) |
| `ESCALATE` | `RCI_ESCALATE_STALE_ASSIGNMENT` | No (se retiene) | Dato obsoleto y sin excepción que lo compense |

---

## Estructura

```text
.
├── .github/workflows/ci.yml     # CI con OPA fijado por versión y checksum
├── contrato.md                  # Esquema de entrada/salida y garantías de confianza
├── integracion_rci.py           # Adaptador Python (sin dependencias externas)
├── policy.rego                  # La política
├── policy_test.rego             # 80 tests de política
└── test_integracion_rci.py      # 64 tests del adaptador
```

---

## Cómo se prueba

Requisitos: Python 3.10+ (usa `match`) y OPA en el `PATH`.

```bash
python3 -m unittest -v
opa fmt --fail policy.rego policy_test.rego
opa check --strict policy.rego policy_test.rego
opa test policy.rego policy_test.rego --coverage
```

144 pruebas en total, con ~99% de cobertura sobre la política. Los tests cubren
los caminos felices, pero sobre todo los que no lo son: fechas imposibles,
excepciones con la ventana invertida, `max_age` a cero, contradicciones entre
estado y timestamp, raíces de input que no son objetos, segundos intercalares.

El CI verifica además una propiedad que un test unitario no puede: que la prueba
de integración **con OPA real** se haya ejecutado de verdad y no quedado omitida
por no encontrar el binario.

---

## Uso

```python
from integracion_rci import Decision, evaluar, obtener_decision

resultado = evaluar(entrada_confiable_del_backend)

match obtener_decision(resultado):
    case Decision.ALLOW:
        pass  # ejecutar
    case Decision.ALLOW_WITH_EXCEPTION:
        pass  # ejecutar y registrar la excepción aplicada
    case Decision.DENY:
        pass  # denegar
    case Decision.ESCALATE:
        pass  # retener y enviar a revisión humana
```

El esquema completo, las garantías de confianza y la semántica exacta de cada
decisión están en [`contrato.md`](contrato.md).
