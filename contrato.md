# Contrato de la política RCI-EXP-001

> **Versión de la política: 3.0.0.** Los cambios respecto a versiones previas están al final, en **Changelog**.
>
> **PDP especializado.** Este proyecto decide acceso a expedientes a partir de una autorización de acción **ya resuelta**, coincidencia de unidad, frescura de la asignación y excepciones aprobadas. Se ejecuta **detrás de un PEP/backend confiable** que construye íntegramente el input (identidad del IAM, permisos ya resueltos, asignación del sistema de expedientes, excepción de un almacén autorizado y hora del servidor). **El cliente final nunca construye el input.** La política no autentica, no gestiona identidades ni roles, no calcula permisos, no consulta bases de datos y no administra excepciones: solo comprueba coherencia y aplicabilidad sobre datos confiables.

## INPUT (lo que el punto de control envía a OPA)

La **raíz del input debe ser un objeto JSON**; un `null`, string, array o número se rechaza como `RCI_DENY_INVALID_INPUT`.

```json
{
  "actor": {
    "id": "u-001",
    "unidad": "UNIDAD_A",
    "acciones_permitidas": ["leer", "modificar"]
  },
  "action": "leer",
  "resource": {
    "expediente_id": "exp-123",
    "unidad_asignada": "UNIDAD_A",
    "asignacion_status": "FRESH",
    "asignacion_timestamp": "2026-06-28T10:00:00Z",
    "asignacion_max_age_seconds": 3600
  },
  "excepcion": {
    "id": "exc-777",
    "actor_id": "u-001",
    "expediente_id": "exp-123",
    "acciones_autorizadas": ["leer"],
    "vigente_desde": "2026-06-28T00:00:00Z",
    "vigente_hasta": "2026-06-29T00:00:00Z",
    "fuente_status": "FRESH",
    "fuente_timestamp": "2026-06-28T10:00:00Z",
    "fuente_max_age_seconds": 3600,
    "aprobada_por": "responsable-x"
  },
  "now": "2026-06-28T10:15:00Z"
}
```

(`excepcion` es `null` cuando no hay excepción activa; el ejemplo la muestra rellena para documentar sus campos.)

Campos:

| Campo | Tipo | Obligatorio | Notas |
|---|---|---|---|
| `actor.id` | string no vacío | sí | identificador único del actor |
| `actor.unidad` | string no vacío | sí | unidad orgánica del actor, según IAM |
| `actor.acciones_permitidas` | array de string no vacío | sí | acciones ya autorizadas por el sistema corporativo (dato confiable del PEP). La política **no** calcula roles ni permisos: solo comprueba pertenencia |
| `action` | string no vacío | sí | acción solicitada; **debe estar en `actor.acciones_permitidas`** para poder concederse. Si se usa excepción, también debe estar en `excepcion.acciones_autorizadas` |
| `resource.expediente_id` | string no vacío | sí | identificador del expediente |
| `resource.unidad_asignada` | string no vacío | sí (si `asignacion_status` es `FRESH`/`STALE`) | unidad a la que el expediente está asignado |
| `resource.asignacion_status` | enum: `FRESH`, `STALE`, `UNAVAILABLE` | sí | estado de frescura del dato, calculado por el adaptador antes de llegar aquí |
| `resource.asignacion_timestamp` | string RFC3339 | sí (si `FRESH`/`STALE`) | cuándo se generó el dato de asignación; se parsea con `time.parse_rfc3339_ns` |
| `resource.asignacion_max_age_seconds` | number ≥ 0 | sí | umbral usado por el adaptador para decidir FRESH vs STALE. **Rego lo usa para detectar contradicciones** (ver *Nota de diseño*), no para recalcular el estado |
| `excepcion` | object o `null` | sí | **la clave debe existir siempre**; usa `null` si no hay excepción activa (si falta la clave, el input es inválido) |
| `excepcion.id` | string no vacío | si `excepcion != null` | identificador único de la excepción; se refleja en el output como `excepcion_id_aplicada` cuando se aplica |
| `excepcion.actor_id` | string no vacío | si `excepcion != null` | a quién beneficia la excepción |
| `excepcion.expediente_id` | string no vacío | si `excepcion != null` | sobre qué expediente |
| `excepcion.acciones_autorizadas` | array de string | si `excepcion != null` | qué acciones cubre; **solo strings no vacíos**. `action` debe estar incluida |
| `excepcion.vigente_desde` | string RFC3339 | si `excepcion != null` | inicio de ventana de validez; se parsea con `time.parse_rfc3339_ns` |
| `excepcion.vigente_hasta` | string RFC3339 | si `excepcion != null` | fin de ventana de validez; se exige `vigente_desde <= vigente_hasta` |
| `excepcion.fuente_status` | enum: `FRESH`, `STALE`, `UNAVAILABLE` | si `excepcion != null` | frescura del propio registro de excepción, independiente de la asignación. **Una excepción solo concede acceso si su `fuente_status == "FRESH"`** |
| `excepcion.fuente_timestamp` | string RFC3339 | si `fuente_status` es `FRESH`/`STALE` | cuándo se leyó el registro de la excepción; Rego contrasta `fuente_status` contra esta edad |
| `excepcion.fuente_max_age_seconds` | number ≥ 0 | si `fuente_status` es `FRESH`/`STALE` | umbral de frescura de la fuente de excepciones |
| `excepcion.aprobada_por` | string no vacío | si `excepcion != null` | trazabilidad de quién aprobó |
| `now` | string RFC3339 (año 1678–2261 inclusive) | sí | momento de evaluación, lo inyecta el punto de control; se parsea con `time.parse_rfc3339_ns` |

**Nota de diseño (responsabilidades y coherencia):**

- **El cálculo del estado (`FRESH`/`STALE`/`UNAVAILABLE`) vive en el adaptador, fuera de Rego.** La política decide *qué hacer* dado un estado, no *cómo calcular* el estado. La asignación y la excepción se evalúan **de forma independiente**: son dos fuentes distintas que pueden desincronizarse.
- **Frescura de la excepción: modelada, no supuesta.** En la 2.0.0 se aceptaba `excepcion.fuente_status` sin contraste. Desde la 2.1.0 la excepción trae su propio `fuente_timestamp` y `fuente_max_age_seconds`, y Rego valida que `fuente_status` no contradiga esa edad (mismo criterio que la asignación). Se optó por **modelar** la frescura de la fuente de excepciones en vez de declararla dentro de la base de confianza, para que una excepción declarada `FRESH` con un registro caducado sea rechazada como input inválido en lugar de conceder acceso.
- **Rego NO recalcula la frescura, pero SÍ detecta contradicciones.** Para este prototipo se optó explícitamente por que Rego contraste el `asignacion_status` declarado contra la edad calculada `now − asignacion_timestamp` frente a `asignacion_max_age_seconds`. Convención: `edad ≤ max_age ⇒ FRESH`; `edad > max_age ⇒ STALE`. Si el estado declarado contradice esa relación (p. ej. `status = FRESH` pero `edad > max_age`), el input se considera **inválido** y se devuelve `RCI_DENY_INVALID_INPUT`. Rego no sobreescribe el estado del adaptador: lo rechaza cuando es incoherente.
- **Comparación temporal por instante, no por string.** Todos los instantes se convierten a nanosegundos con `time.parse_rfc3339_ns` antes de compararlos. Esto hace correcta la comparación aunque `now` y la ventana de la excepción vengan con **offsets horarios distintos** (p. ej. `Z` vs `+02:00`), cosa que una comparación léxica de strings haría mal.

**Reglas temporales (resumen normativo):**

- La comparación usa el **instante real con precisión de nanosegundos**; nunca comparación léxica.
- `now` **procede del backend/servidor**; el cliente no lo aporta.
- Un `timestamp` **futuro** (`> now`) es **inválido** (`RCI_DENY_INVALID_INPUT`).
- **No hay tolerancia de reloj implícita** ni configurable en esta versión.
- Convención: `edad ≤ max_age ⇒ FRESH`; `edad > max_age ⇒ STALE`.
- Con **`max_age_seconds = 0`** solo se considera `FRESH` una edad **exactamente igual a cero** (`now == timestamp`); cualquier edad positiva declarada `FRESH` es incoherente → inválido.
- Los **segundos intercalares `:60`** **no** están admitidos por este contrato, aunque otras interpretaciones de RFC3339 puedan aceptarlos.
- **Rango de años realmente aceptado por la implementación: `1678..2261` inclusive** (límite de `time.parse_rfc3339_ns` como ns `int64`). Fuera de él → inválido.
- **Fechas validadas por calendario antes de parsear.** La forma RFC3339 se comprueba con regex y, además, se valida el calendario real (rango de mes, día según mes y año bisiesto, hora, minuto, segundo y offset). Solo un instante que supere todo esto llega a `time.parse_rfc3339_ns`. Así una fecha con forma válida pero imposible (p. ej. `2026-02-31`) se rechaza como input inválido y la política **no aborta ni siquiera con `--strict-builtin-errors`**.
- **Representabilidad, no solo validez.** Una fecha puede tener forma y calendario correctos y aun así no ser representable por OPA como nanosegundos `int64` (el rango útil de `time.parse_rfc3339_ns` cubre aproximadamente ese lapso). Por eso el año se limita a **`1678..2261` inclusive** **antes** de parsear y, además, se exige que el parseo **devuelva realmente un número** antes de usarlo. Fechas fuera de rango (p. ej. años `0000` o `9999`) → `RCI_DENY_INVALID_INPUT`, con `resultado` siempre definido.

## OUTPUT (lo que OPA devuelve)

La política **siempre** devuelve un objeto `resultado` estructurado y completo, incluso ante un input inválido o incompleto. `decision`, `reason_code` y `execution_allowed` se emiten **juntos, desde un único objeto `outcome`**, de modo que no pueden quedar desincronizados entre sí.

```json
{
  "decision": "ALLOW",
  "reason_code": "RCI_ALLOW_UNIT_MATCH",
  "execution_allowed": true,
  "regla": "RCI-EXP-001",
  "actor_id": "u-001",
  "expediente_id": "exp-123",
  "asignacion_status": "FRESH",
  "excepcion_id_aplicada": null,
  "excepcion_existente_no_utilizada": false,
  "validation_errors": [],
  "evaluated_at": "2026-06-28T10:15:00Z",
  "policy_version": "3.0.0"
}
```

| Campo | Tipo | Notas |
|---|---|---|
| `decision` | enum: `ALLOW`, `ALLOW_WITH_EXCEPTION`, `ESCALATE`, `DENY` | la decisión final |
| `reason_code` | string (enum cerrado, estable) | código fijo: `RCI_DENY_INVALID_INPUT`, `RCI_DENY_ACTION_NOT_ALLOWED`, `RCI_DENY_SOURCE_UNAVAILABLE`, `RCI_ALLOW_UNIT_MATCH`, `RCI_ALLOW_EXCEPTION_APPLIED`, `RCI_DENY_UNIT_MISMATCH`, `RCI_ESCALATE_STALE_ASSIGNMENT` |
| `execution_allowed` | boolean | `true` solo para `ALLOW` y `ALLOW_WITH_EXCEPTION`; `false` para `DENY`, `ESCALATE` e input inválido |
| `regla` | string | identificador fijo de la regla evaluada |
| `actor_id` / `expediente_id` | string \| null | eco de auditoría **saneado por tipo**: string si el input lo trae como string, `null` en cualquier otro caso |
| `asignacion_status` | string \| null | el estado de frescura usado; uno de `FRESH`/`STALE`/`UNAVAILABLE`, o `null` si ausente o mal tipado |
| `excepcion_id_aplicada` | string \| null | `excepcion.id` de la excepción efectivamente aplicada; solo en `ALLOW_WITH_EXCEPTION`, `null` en el resto |
| `excepcion_existente_no_utilizada` | boolean | `true` solo cuando la decisión fue `ALLOW` por coincidencia directa **y** existía además una excepción básica aplicable a ese mismo actor/expediente/acción. Señal de auditoría |
| `validation_errors` | array de string | lista **ordenada** de problemas del input; vacía (`[]`) cuando el input es válido. No vacía ⇔ `reason_code == "RCI_DENY_INVALID_INPUT"` |
| `evaluated_at` | string \| null | eco de `input.now` **saneado por tipo**: string o `null` |
| `policy_version` | string (semver) | versión de la política |

### Validación de input → `RCI_DENY_INVALID_INPUT`

Antes de la lógica de negocio, la política valida el input. Si `validation_errors` no está vacía, `outcome` es:

```json
{ "decision": "DENY", "reason_code": "RCI_DENY_INVALID_INPUT", "execution_allowed": false }
```

Se marca inválido (entre otros) cuando:

- Falta o no es string alguno de `actor.id`, `actor.unidad`, `action`, `resource.expediente_id`.
- `asignacion_status` está ausente o fuera del enum.
- `asignacion_max_age_seconds` no es número **o es negativo** (`< 0`).
- `now` no es RFC3339 válido.
- Con `FRESH`/`STALE`: falta `unidad_asignada`, o `asignacion_timestamp` falta/no es RFC3339, **o `asignacion_timestamp` está en el futuro (`> now`)** — un dato futuro no puede ser FRESH.
- La clave `excepcion` **no existe** (es obligatoria aunque valga `null`); o está presente y no es objeto ni `null`; o, siendo objeto, le falta/rompe algún campo (`id`, `actor_id`, `expediente_id`, `acciones_autorizadas`, `vigente_desde`, `vigente_hasta`, `fuente_status`, `aprobada_por`).
- Con `excepcion.fuente_status` `FRESH`/`STALE`: falta `fuente_timestamp` (o no es RFC3339 o es futuro), o `fuente_max_age_seconds` (o es negativo), **o `fuente_status` contradice su edad real** (mismo criterio que la asignación).
- La **raíz** del input no es un objeto JSON (es `null`, string, array o número).
- Algún campo string obligatorio está **vacío**: `actor.id`, `actor.unidad`, `action`, `resource.expediente_id`, `resource.unidad_asignada`, o los ids / `aprobada_por` de la excepción.
- Una fecha con forma+calendario válidos **no es representable** por OPA (año fuera de 1678–2261, p. ej. `0000` o `9999`), o el parseo no produce un número.
- Alguna fecha tiene forma RFC3339 pero es **imposible en el calendario** (mes/día/hora/offset fuera de rango, p. ej. `2026-02-31`).
- La excepción tiene `vigente_desde` **posterior** a `vigente_hasta`, o `acciones_autorizadas` contiene algún elemento que no es string o es string vacío.
- El estado de la asignación **contradice** su timestamp/`max_age` (ver *Nota de diseño*).

### Lógica de decisión (declarativa: reglas mutuamente excluyentes)

Rego evalúa un conjunto de reglas; para cualquier `input` **válido** exactamente una rama de `outcome` se satisface. Las condiciones se excluyen mutuamente por construcción.

Funciones auxiliares (funciones puras de `input`):

- `input_valido` ⇔ `validation_errors` está vacía.
- `accion_permitida` ⇔ `action ∈ actor.acciones_permitidas` (lista confiable ya resuelta por el sistema corporativo; la política solo comprueba pertenencia).
- `fuente_disponible` ⇔ `resource.asignacion_status != "UNAVAILABLE"`.
- `unidad_coincide` ⇔ `resource.asignacion_status == "FRESH"` y `actor.unidad == resource.unidad_asignada`.
- `excepcion_basica_aplicable` ⇔ existe `excepcion`, coincide en `actor_id`, `expediente_id`, `action ∈ acciones_autorizadas`, y `now` está en la ventana `[vigente_desde, vigente_hasta]` (comparación por nanosegundos, ambos extremos **inclusive**).
- `excepcion_valida` ⇔ `excepcion_basica_aplicable` **y** `excepcion.fuente_status == "FRESH"`. Una excepción solo es válida si ella misma está `FRESH`, tanto si la asignación está `FRESH` como `STALE`.
- `excepcion_aplicable_y_valida` ⇔ `resource.asignacion_status ∈ {FRESH, STALE}` y `excepcion_valida`.

**El control de acción se evalúa ANTES que unidad y excepciones.** Una excepción **nunca** puede conceder una acción ausente de `actor.acciones_permitidas`.

Ramas de `outcome` (mutuamente excluyentes):

| condición | `decision` | `reason_code` | `execution_allowed` |
|---|---|---|---|
| `not input_valido` | `DENY` | `RCI_DENY_INVALID_INPUT` | `false` |
| `input_valido`, `not accion_permitida` | `DENY` | `RCI_DENY_ACTION_NOT_ALLOWED` | `false` |
| `input_valido`, `accion_permitida`, `not fuente_disponible` | `DENY` | `RCI_DENY_SOURCE_UNAVAILABLE` | `false` |
| `input_valido`, `accion_permitida`, `fuente_disponible`, `unidad_coincide` | `ALLOW` | `RCI_ALLOW_UNIT_MATCH` | `true` |
| `input_valido`, `accion_permitida`, `fuente_disponible`, `not unidad_coincide`, `excepcion_aplicable_y_valida` | `ALLOW_WITH_EXCEPTION` | `RCI_ALLOW_EXCEPTION_APPLIED` | `true` |
| `input_valido`, `accion_permitida`, `fuente_disponible`, `not unidad_coincide`, `not excepcion_aplicable_y_valida`, `status == FRESH` | `DENY` | `RCI_DENY_UNIT_MISMATCH` | `false` |
| `input_valido`, `accion_permitida`, `fuente_disponible`, `not unidad_coincide`, `not excepcion_aplicable_y_valida`, `status == STALE` | `ESCALATE` | `RCI_ESCALATE_STALE_ASSIGNMENT` | `false` |

### Tabla resumen

| acción permitida | `asignacion_status` | unidad coincide | excepción `FRESH` válida | → `decision` |
|---|---|---|---|---|
| (input inválido/incoherente) | — | — | — | `DENY` (`RCI_DENY_INVALID_INPUT`) |
| no | — | — | — | `DENY` (`RCI_DENY_ACTION_NOT_ALLOWED`) |
| sí | UNAVAILABLE | — | — | `DENY` (`RCI_DENY_SOURCE_UNAVAILABLE`) |
| sí | FRESH | sí | (no modifica la decisión) | `ALLOW` |
| sí | FRESH | no | sí | `ALLOW_WITH_EXCEPTION` |
| sí | FRESH | no | no | `DENY` (`RCI_DENY_UNIT_MISMATCH`) |
| sí | STALE | no aplica\* | sí | `ALLOW_WITH_EXCEPTION` |
| sí | STALE | no aplica\* | no | `ESCALATE` (retenida) |

\* Con `STALE` no se compara unidad porque el propio dato de asignación no es confiable — por eso siempre se busca excepción `FRESH` o se escala.

### Tratamiento de decisiones por el consumidor

El PEP debe tratar **explícitamente** las cuatro decisiones (no reducirlas a un booleano):

- **`ALLOW`** → ejecutar.
- **`ALLOW_WITH_EXCEPTION`** → ejecutar, pero como mínimo **registrar la excepción aplicada** conservando `reason_code` y `excepcion_id_aplicada`.
- **`DENY`** (cualquier `reason_code`) → denegar.
- **`ESCALATE`** → **retener** la operación y activar revisión/retención; **no** convertirla silenciosamente en una denegación ordinaria.

En la integración Python, `acceso_permitido()` devuelve `True` solo para `ALLOW` y `False` para cualquier `DENY`; `ALLOW_WITH_EXCEPTION` y `ESCALATE` lanzan `DecisionRequiereTratamientoExplicito` para impedir que la API oculte estos casos. El sistema de auditoría y el workflow de revisión son responsabilidad del consumidor; este proyecto solo evita ocultarlos.

---

## Integración Python (frontera del cliente)

El módulo `integracion_rci.py` envuelve `opa eval` por subprocess y añade garantías en la **frontera Python**:

- **Vínculo respuesta ↔ petición.** El resultado se valida además contra el input original: `actor_id`, `expediente_id`, `asignacion_status` y `evaluated_at` deben corresponder a la petición; en `ALLOW_WITH_EXCEPTION`, `excepcion_id_aplicada` debe ser el `excepcion.id` enviado; en el resto es `null`. No se confía en una respuesta que refleje otro actor, expediente, estado, excepción o instante. Para `RCI_DENY_INVALID_INPUT` se comparan los ecos **saneados** (string válido → se refleja; tipo incorrecto/ausente → `null`; estado fuera de enum → `null`).
- **Normalización de la salida.** Los **campos desconocidos** que devuelva OPA **no participan en la decisión y se eliminan en la frontera Python**: el consumidor solo recibe las claves contractuales. No se rechazan automáticamente para permitir cambios compatibles en la política.
- **Serialización estricta.** La raíz del input debe ser un objeto; se serializa con `allow_nan=False`. `NaN`, infinitos, objetos no serializables y raíces que no sean objeto se rechazan de forma controlada (`ErrorDeEvaluacion`), sin excepciones crudas.
- **Ejecución segura de OPA.** El binario se resuelve una sola vez a una **ruta absoluta** verificada (existe, es archivo, es ejecutable) y se ejecuta sin shell. Se puede inyectar `opa_path=` **solo para pruebas/desarrollo**.
- **Política empaquetada.** El uso normal emplea la política junto al módulo. Una **política personalizada** (`policy_path=`) es **solo para pruebas o desarrollo** y requiere `permitir_politica_personalizada=True`; nunca debe provenir de datos del cliente. Se expone `sha256_politica()` para auditoría/diagnóstico (no es un sistema de integridad completo).
- **Auditoría mínima.** `crear_registro_auditoria()` revalida primero la respuesta contra el contrato y la petición original, y después construye (sin persistir) un diccionario con actor, unidad, expediente, acción, estado, decisión, `reason_code`, `execution_allowed`, `excepcion_id_aplicada`, `aprobada_por`, `evaluated_at`, versión y SHA-256 de la política. El consumidor decide dónde guardarlo.
- **Limitación de rendimiento.** Cada evaluación lanza un **subprocess `opa eval`**; es adecuado para volúmenes moderados, no para rutas de altísimo caudal. Un OPA Server/sidecar o los bundles quedan **fuera del alcance** de esta versión (ver recomendaciones futuras).

## Migración 2.3.1 → 3.0.0

Cambio **mayor** (input y decisiones cambian). Para migrar:

1. **Input:** añade `actor.acciones_permitidas` (array de strings no vacíos, **obligatorio**) a cada petición. Si falta o no es array → `RCI_DENY_INVALID_INPUT`.
2. **Nueva decisión:** maneja `RCI_DENY_ACTION_NOT_ALLOWED` (input válido pero `action ∉ acciones_permitidas`). No confundir con `RCI_DENY_INVALID_INPUT`. Se evalúa **antes** de unidad y excepciones; una excepción no puede conceder una acción no permitida.
3. **Versión:** `policy_version` pasa a `"3.0.0"` en política, contrato, integración y pruebas.
4. **Consumidor Python:** `evaluar(...)` usa argumentos **solo por nombre** (`policy_path=`, `permitir_politica_personalizada=`, `timeout=`, `opa_path=`) y devuelve el resultado **normalizado**. `acceso_permitido()` ahora **lanza** `DecisionRequiereTratamientoExplicito` para `ALLOW_WITH_EXCEPTION` y `ESCALATE`; usa `obtener_decision()` + `match` para tratamiento exhaustivo.
5. Sin cambios en las reglas de frescura, excepciones ni en la responsabilidad del adaptador.

## Changelog 3.0.0 (autorización por acción + frontera de confianza)

1. **`actor.acciones_permitidas`** (array de strings no vacíos, obligatorio): lista de acciones **ya resuelta** por el sistema corporativo (dato confiable del PEP). La política solo comprueba pertenencia; no calcula roles ni permisos.
2. **Nueva decisión `RCI_DENY_ACTION_NOT_ALLOWED`**: input válido pero acción no permitida. Se comprueba **antes** de unidad y excepciones; una excepción no puede conceder una acción ausente de la lista.
3. **Frontera de confianza documentada**: PDP especializado tras un PEP confiable; el cliente final no construye el input.
4. **Integración Python endurecida**: vínculo respuesta↔petición, normalización de salida, serialización estricta, validación de timeout, ejecución segura del binario, política empaquetada + SHA-256, auditoría mínima y tratamiento explícito de `ALLOW_WITH_EXCEPTION`/`ESCALATE`.
5. **Corrección documental** del rango de años a `1678..2261` inclusive (se elimina la mención a `2262`).

## Changelog 2.3.1 (saneado de auditoría)

17. **Ecos de auditoría saneados por tipo.** `actor_id`, `expediente_id`, `asignacion_status` y `evaluated_at` reflejan el valor del input solo si tiene el tipo contractual (string; enum en `asignacion_status`); en caso contrario devuelven `null`. Evita arrastrar valores mal tipados (p. ej. `actor_id` numérico) a los metadatos al rechazar un input inválido. **No** cambia decisión, `reason_code` ni `validation_errors`.

## Changelog 2.3.0 (endurecimiento)

15. **Representabilidad de fechas.** No basta con forma+calendario: el año se limita al rango representable como ns `int64` (~1678–2261) y se exige que `time.parse_rfc3339_ns` devuelva un número antes de usarlo. Años como `0000`/`9999` → `RCI_DENY_INVALID_INPUT` sin abortar.
16. **Strings vacíos rechazados** en `actor.id`, `actor.unidad`, `action`, `resource.expediente_id`, `resource.unidad_asignada`, y en `excepcion.id`, `excepcion.actor_id`, `excepcion.expediente_id`, `excepcion.aprobada_por`.

## Changelog 2.2.0 (endurecimiento)

11. **Raíz del input validada.** Si `input` no es un objeto (null, string, array, número) → `RCI_DENY_INVALID_INPUT`, con `resultado` igualmente definido.
12. **Ventana de excepción coherente.** Se rechaza `vigente_desde > vigente_hasta`.
13. **`acciones_autorizadas` saneada.** Debe ser un array de strings no vacíos.
14. **Fechas a prueba de imposibles.** Validación de calendario (mes, día con bisiesto, hora, offset) antes de parsear; `time.parse_rfc3339_ns` solo recibe fechas reales, de modo que la política no falla ni con `--strict-builtin-errors`.

## Changelog 2.1.0

7. **`excepcion` obligatorio de verdad.** Se valida que la **clave** exista aunque su valor sea `null`; si falta, `RCI_DENY_INVALID_INPUT` (antes se trataba una clave ausente como `null`).
8. **Nuevas validaciones de la asignación:** `asignacion_timestamp <= now` (un timestamp futuro no puede ser FRESH) y `asignacion_max_age_seconds >= 0`.
9. **Frescura de la excepción modelada.** Nuevos `excepcion.fuente_timestamp` y `excepcion.fuente_max_age_seconds` (obligatorios si `fuente_status` es FRESH/STALE); Rego valida que `fuente_status` no contradiga la edad real de la fuente, igual que hace con la asignación.
10. **Redacción del contrato:** "la excepción no se evalúa" → "la excepción no modifica la decisión de autorización".

## Changelog 2.0.0

1. **Excepción siempre `FRESH` para conceder acceso.** `excepcion_valida` exige `excepcion.fuente_status == "FRESH"` tanto con asignación `FRESH` como `STALE`. Una excepción `STALE`/`UNAVAILABLE` ya no compensa una discrepancia de unidad ni una asignación obsoleta.
2. **Comparación temporal por instante.** `now`, `vigente_desde`, `vigente_hasta` (y `asignacion_timestamp`) se parsean con `time.parse_rfc3339_ns`; se acabaron las comparaciones de strings. Correcto ante offsets horarios.
3. **Resultado siempre estructurado + validación de input.** Nuevo `reason_code` `RCI_DENY_INVALID_INPUT` y nuevo campo `validation_errors`. Ante input ausente/incompleto/mal tipado, la política devuelve un `resultado` completo en lugar de quedar indefinida.
4. **`outcome` unificado.** `decision`, `reason_code` y `execution_allowed` se emiten desde un único objeto, evitando que reglas separadas puedan contradecirse.
5. **`excepcion.id` (input) y `excepcion_id_aplicada` (output).** Trazabilidad de qué excepción concreta se aplicó.
6. **Detección de contradicciones estado/timestamp/max_age.** Rego confía en el adaptador para el estado, pero rechaza como `RCI_DENY_INVALID_INPUT` los inputs donde el estado declarado contradice la edad calculada.
