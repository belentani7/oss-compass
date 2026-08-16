# OSS Compass

[![CI](https://github.com/belentani7/oss-compass/actions/workflows/ci.yml/badge.svg)](https://github.com/belentani7/oss-compass/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/security-policy-brightgreen.svg)](SECURITY.md)

**OSS Compass** es una implementación inicial del **PVC-U (Protocolo Universal de Validación)**: una capa agnóstica de tecnología para validar datos, respuestas de IA y acciones antes de aceptarlas, dejando un sobre verificable y un resultado auditable.

> El objetivo no es prometer perfección automática. El objetivo es hacer explícitas las reglas, conservar evidencia y exigir confirmación independiente antes de aceptar decisiones sensibles.

## Qué incluye esta versión

La primera versión implementa un núcleo pequeño y componible. Calcula un hash estable del payload, ejecuta reglas declarativas, genera un `ValidationEnvelope` con resultados y permite confirmar el sobre con **tres nodos independientes**, usando por defecto un quórum de **2 de 3**. La confirmación es una barrera de decisión; no sustituye la autenticación de red, la firma criptográfica con claves gestionadas ni la revisión humana en operaciones de alto riesgo.

| Componente | Responsabilidad |
|---|---|
| `ValidationEnvelope` | Identifica el sujeto, perfil, hash del payload, reglas y resultados. |
| `ValidationResult` | Expresa código PVC, esfera, estado y mensaje accionable. |
| `confirm_three_nodes` | Reúne tres decisiones y aplica un quórum configurable. |
| Perfiles | Permiten activar reglas según tipo de proyecto o sistema de IA. |
| Ledger futuro | Persistirá sobres y receipts para auditoría e investigación de fallos. |

## Inicio rápido

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest
```

```python
from oss_compass import confirm_three_nodes, required_fields, validate

payload = {"intent": "deploy", "environment": "staging"}
envelope = validate(
    payload,
    subject="deployment-request-001",
    profile="agent-action",
    rules=[required_fields("intent", "environment")],
)
receipt = confirm_three_nodes(
    envelope,
    {"policy-node": True, "risk-node": True, "audit-node": False},
)

assert receipt.accepted is True
print(envelope.envelope_id, receipt.accepted_nodes)
```

## Diseño del módulo de tres nodos

Cada nodo recibe el mismo `envelope_id` y emite una decisión independiente. Con tres nodos y un quórum de dos, una decisión se acepta cuando al menos dos nodos la aprueban. Las decisiones se ordenan de forma estable y el receipt conserva el identificador del sobre, el estado de cada nodo, una huella de la confirmación y el motivo de rechazo cuando exista.

```text
                    +------------------+
                    | Validation       |
                    | Envelope         |
                    +--------+---------+
                             |
          +------------------+------------------+
          |                  |                  |
   +------v------+    +------v------+    +------v------+
   | Policy node |    | Risk node   |    | Audit node  |
   | decision    |    | decision    |    | decision    |
   +------+------+
          \                  |                  /
           +-----------------+-----------------+
                             |
                    +--------v---------+
                    | 2-of-3 receipt   |
                    | accept / reject  |
                    +------------------+
```

El módulo no simula una red ni afirma tolerancia bizantina. En esta fase representa el contrato de decisión y el quórum; la comunicación autenticada, la rotación de claves, la resistencia a nodos maliciosos y el almacenamiento inmutable son ampliaciones planificadas.

## Universalidad y perfiles

El protocolo está pensado para adaptadores de dominio. Un perfil puede activar validaciones distintas para una API, un sistema IoT, una aplicación sanitaria, un flujo financiero o un agente con IA. Las validaciones específicas de IA se incorporarán como reglas separadas para entradas y salidas, comportamiento semántico, trazabilidad del modelo, drift y permisos dinámicos.

Las reglas futuras deberán ser deterministas cuando sea posible, versionadas y observables. Cuando una regla dependa de un modelo, el resultado debe incluir la versión del modelo, la política utilizada y la evidencia suficiente para reproducir la evaluación.

## Estado del proyecto

OSS Compass se encuentra en **alpha temprana**. La API pública puede cambiar. No utilices esta versión como único control para pagos, borrado de datos, decisiones clínicas, seguridad física o cualquier operación irreversible.

## Contribuir

Consulta [CONTRIBUTING.md](CONTRIBUTING.md), abre una issue reproducible o propone una extensión de perfil. Las contribuciones deben incluir pruebas y explicar el impacto sobre el contrato del sobre o el quórum.

## Licencia

Publicado bajo la licencia [MIT](LICENSE).
