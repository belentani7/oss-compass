# OSS Compass

[![CI](https://github.com/belentani7/oss-compass/actions/workflows/ci.yml/badge.svg)](https://github.com/belentani7/oss-compass/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/security-policy-brightgreen.svg)](SECURITY.md)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/belentani7/oss-compass/badge)](https://scorecard.dev/viewer/?uri=github.com/belentani7/oss-compass)

**OSS Compass** es una implementación inicial del **PVC-U (Protocolo Universal de Validación)**: una capa agnóstica de tecnología para validar datos, respuestas de IA y acciones antes de aceptarlas, dejando un sobre verificable y un resultado auditable.

> El objetivo no es prometer perfección automática. El objetivo es hacer explícitas las reglas, conservar evidencia y exigir confirmación independiente antes de aceptar decisiones sensibles.

## Qué incluye esta versión

La versión actual implementa un núcleo pequeño y componible. Calcula un hash estable del payload, ejecuta reglas declarativas, genera un `ValidationEnvelope` con resultados y permite confirmar el sobre con **tres nodos independientes**, usando por defecto un quórum de **2 de 3**. Conserva el transporte HMAC v1 por compatibilidad y añade PVC-U v2 con firmas **Ed25519**, lista explícita de coordinadores confiables, nonce anti-replay acotado, ventana temporal, respuestas firmadas y un ledger local encadenado por hash. Ed25519 permite que los nodos verifiquen una solicitud sin conocer la clave privada del coordinador [1]. La confirmación es una barrera de decisión; no sustituye TLS, almacenamiento seguro de claves, procesos independientes ni revisión humana en operaciones de alto riesgo.

| Componente | Responsabilidad |
|---|---|
| `ValidationEnvelope` | Identifica el sujeto, perfil, hash del payload, reglas y resultados. |
| `ValidationResult` | Expresa código PVC, esfera, estado y mensaje accionable. |
| `confirm_three_nodes` | Reúne decisiones locales y aplica un quórum configurable. |
| `NodeServer` / `NodeConfig` | Transporte HMAC v1 para compatibilidad y pruebas locales. |
| `Ed25519NodeServer` / `SignedNodeConfig` | Nodo PVC-U v2 con clave privada propia y allow-list de claves públicas de coordinadores. |
| `confirm_over_network` | Cliente HMAC v1 que consulta tres nodos y aplica 2-de-3. |
| `confirm_over_ed25519_network` | Cliente PVC-U v2 que verifica respuestas Ed25519 y aplica 2-de-3. |
| `ValidationLedger` | Cadena NDJSON append-only de receipts con verificación offline del head hash. |
| Perfiles | Permiten activar reglas según tipo de proyecto o sistema de IA. |

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

El módulo de compatibilidad `confirm_three_nodes` no simula una red. `NodeServer` y `confirm_over_network` mantienen la versión HMAC v1. Para integraciones nuevas, PVC-U v2 usa `Ed25519NodeServer` y `confirm_over_ed25519_network`: el coordinador firma con su clave privada, cada nodo acepta solo coordinadores configurados mediante clave pública, y las respuestas se verifican con la clave pública propia del nodo. El transporte de desarrollo sigue siendo HTTP local; en producción debe envolverse en TLS y conectar tres procesos o máquinas independientes. La resistencia bizantina, el descubrimiento de nodos, la rotación automática y el almacenamiento inmutable quedan fuera del alcance de esta release.

### Confirmación distribuida por 3 nodos

```python
from oss_compass import NodeConfig, NodeServer, confirm_over_network

servers = [
    NodeServer(NodeConfig(node, "127.0.0.1", 0, f"secret-{node}"))
    for node in ("node-a", "node-b", "node-c")
]
configs = tuple(server.start() for server in servers)
try:
    receipt = confirm_over_network(envelope, configs)
    assert receipt.accepted  # 2 de 3 como mínimo; 3 de 3 en el caso normal
finally:
    for server in servers:
        server.stop()
```

La suite cubre aceptación 3-de-3, divergencia de un nodo, pérdida de un nodo, firma inválida, replay de nonce, coordinador no confiable, manipulación del ledger y reordenación de entradas. No se deben reutilizar claves de fixture en producción.

### PVC-U v2: firmas Ed25519 y confianza explícita

```python
from oss_compass import (
    CoordinatorIdentity,
    Ed25519NodeServer,
    SignedNodeConfig,
    confirm_over_ed25519_network,
    generate_keypair,
)

coordinator_private, coordinator_public = generate_keypair()
coordinator = CoordinatorIdentity("release-coordinator", coordinator_private)
servers = []
for node_id in ("node-a", "node-b", "node-c"):
    node_private, _node_public = generate_keypair()
    server = Ed25519NodeServer(
        SignedNodeConfig(node_id, "127.0.0.1", 0, node_private, {"release-coordinator": coordinator_public})
    )
    server.start()
    servers.append(server)
try:
    receipt = confirm_over_ed25519_network(envelope, coordinator, tuple(server.endpoint() for server in servers))
    assert receipt.accepted
finally:
    for server in servers:
        server.stop()
```

Las claves privadas se generan y almacenan fuera del repositorio. La aplicación solo necesita distribuir las claves públicas de coordinadores y nodos por un canal autenticado. Consulta [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md) antes de operar el protocolo v2.

### Ledger verificable

`ValidationLedger` encadena cada decisión con SHA-256; SHA-256 es un mínimo recomendado por NIST para nuevos protocolos que requieren interoperabilidad [2]. El ledger detecta modificación, reordenación, inserción o truncamiento cuando se compara contra un head hash confiable almacenado fuera del archivo.

```python
from pathlib import Path
from oss_compass import ValidationLedger

ledger = ValidationLedger()
entry = ledger.append(envelope, receipt)
Path("receipts.ndjson").write_text(ledger.to_ndjson(), encoding="utf-8")
assert ledger.verify(expected_head_hash=entry.entry_hash).valid
```

```bash
oss-compass ledger-verify receipts.ndjson --head "<head-hash-confiable>" --json
```

El ledger es local y append-only a nivel de formato, no una base de datos distribuida ni un registro inmutable. Ancla periódicamente el `head_hash` en un sistema independiente de control de cambios, almacenamiento WORM o servicio de transparencia según el riesgo.

## Universalidad y perfiles

El protocolo está pensado para adaptadores de dominio. Un perfil puede activar validaciones distintas para una API, un sistema IoT, una aplicación sanitaria, un flujo financiero o un agente con IA. Las validaciones específicas de IA se incorporarán como reglas separadas para entradas y salidas, comportamiento semántico, trazabilidad del modelo, drift y permisos dinámicos.

Las reglas futuras deberán ser deterministas cuando sea posible, versionadas y observables. Cuando una regla dependa de un modelo, el resultado debe incluir la versión del modelo, la política utilizada y la evidencia suficiente para reproducir la evaluación.

## Estado del proyecto

OSS Compass se encuentra en **alpha temprana**. La API pública puede cambiar. No utilices esta versión como único control para pagos, borrado de datos, decisiones clínicas, seguridad física o cualquier operación irreversible.

## Contribuir

Consulta [CONTRIBUTING.md](CONTRIBUTING.md), abre una issue reproducible o propone una extensión de perfil. Las contribuciones deben incluir pruebas y explicar el impacto sobre el contrato del sobre o el quórum.

## Licencia

Publicado bajo la licencia [MIT](LICENSE).

## Referencias

[1] [Cryptography — Ed25519 signing](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/)

[2] [NIST — Policy on Hash Functions](https://csrc.nist.gov/projects/hash-functions/nist-policy-on-hash-functions)

## Auditoría 3×3 por cambio

Cada cambio puede auditarse con `audit_change`. El protocolo exige exactamente tres nodos (`node-a`, `node-b` y `node-c`) y tres niveles por nodo: **integridad**, **política** y **riesgo**. En total se verifican nueve controles independientes.

La puntuación global se normaliza a una escala de 0 a 10. Un cambio recibe **10/10 únicamente cuando los nueve controles pasan**. Además, el cambio solo queda aprobado cuando al menos dos nodos alcanzan el resultado completo, aplicando un quórum fijo de 2-de-3.

```python
from oss_compass import audit_change

result = audit_change(
    "change-042",
    {"action": "release", "version": "0.2.0"},
    {
        "node-a": {"integrity": True, "policy": True, "risk": True},
        "node-b": {"integrity": True, "policy": True, "risk": True},
        "node-c": {"integrity": True, "policy": True, "risk": True},
    },
)

assert result.score == 10.0
assert result.accepted is True
```

Si un solo nivel falla, la puntuación cae por debajo de 10/10 y el cambio no se marca como aprobado. El resultado incluye el hash del cambio, el estado de cada nodo, la evidencia por nivel y los nodos que alcanzaron aprobación completa.

## Gate estricto de código línea por línea

Para cambios de código, `audit_code_lines` aplica una regla más estricta que el quórum normal. Cada línea modificada debe ser revisada por `node-a`, `node-b` y `node-c` en los tres niveles de **integridad**, **política** y **riesgo**. Cada control vale 10 puntos cuando pasa y 0 cuando falla.

El cambio completo solo pasa si **todas las líneas obtienen 10/10**. Una única línea con un nivel fallido rechaza todo el cambio, aunque las demás líneas estén aprobadas. La auditoría también conserva el hash de cada línea para que el resultado pueda asociarse al contenido exacto revisado.

```python
from oss_compass import audit_code_lines

lines = ["x = 1", "return x"]
checks = {
    node: {
        1: {"integrity": True, "policy": True, "risk": True},
        2: {"integrity": True, "policy": True, "risk": True},
    }
    for node in ("node-a", "node-b", "node-c")
}
result = audit_code_lines("change-100", lines, checks)
assert result.score == 10.0
assert result.passed is True
```

Este mecanismo no marca automáticamente todas las líneas como aprobadas: requiere que los resultados de los tres nodos sean proporcionados de forma explícita. Por ello, una línea sin auditoría completa tampoco pasa.

## Auditoría de hasta 5.000 líneas

El gate admite auditorías reales de entre una y **5.000 líneas modificadas por cambio**. Cada línea genera un registro independiente con número de línea, hash de contenido, tres nodos y tres niveles. El informe no se basa en una muestra: evalúa la colección completa y solo devuelve `passed=True` cuando las 5.000 líneas, si existen, tienen 10/10.

El límite protege el tamaño y la legibilidad del informe. Un cambio de 5.001 líneas se rechaza y debe dividirse en cambios auditables más pequeños. La puntuación 10/10 representa que los tres nodos han aportado verificaciones positivas para integridad, política y riesgo; no debe interpretarse como una garantía absoluta de seguridad ni reemplaza revisión humana especializada.
