# RCI-EXP-001 — política de acceso a expedientes

Implementación de referencia de la política **RCI-EXP-001 v3.0.0** con:

- política Open Policy Agent/Rego;
- contrato de entrada y salida;
- integración Python sin dependencias externas;
- tests unitarios Python y tests Rego;
- workflow de GitHub Actions.

## Estructura obligatoria

```text
.
├── .github/workflows/ci.yml
├── contrato.md
├── integracion_rci.py
├── policy.rego
├── policy_test.rego
└── test_integracion_rci.py
```

No añadas sufijos como `(13)` o `(12)` a esos nombres: la integración y el CI
buscan los nombres canónicos mostrados arriba.

## Requisitos locales

- Python 3.10 o posterior.
- OPA en el `PATH`. En macOS con Homebrew:

```bash
brew install opa
```

## Ejecutar las pruebas

Desde la raíz del proyecto:

```bash
python3 -m unittest -v
opa fmt --fail policy.rego policy_test.rego
opa check --strict policy.rego policy_test.rego
opa test policy.rego policy_test.rego --coverage
```

Las pruebas Python marcadas como integración real se omiten localmente cuando no
encuentran OPA. En GitHub Actions, el workflow instala OPA y falla si dichas
pruebas quedan omitidas.

## Uso mínimo

```python
from integracion_rci import Decision, evaluar, obtener_decision

resultado = evaluar(entrada_confiable_del_backend)

match obtener_decision(resultado):
    case Decision.ALLOW:
        pass  # ejecutar
    case Decision.ALLOW_WITH_EXCEPTION:
        pass  # ejecutar y registrar la excepción
    case Decision.DENY:
        pass  # denegar
    case Decision.ESCALATE:
        pass  # retener y enviar a revisión
```

Consulta `contrato.md` para el esquema completo, las garantías de confianza y la
semántica exacta de cada decisión.
