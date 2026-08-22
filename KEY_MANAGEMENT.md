# Gestión de claves para PVC-U v2

PVC-U v2 utiliza Ed25519 para autenticar coordinadores y nodos. Una firma demuestra control de una clave privada, pero **no** soluciona por sí sola el transporte, la autorización operativa, la disponibilidad, la independencia administrativa ni la custodia de credenciales.

| Material | Propietario | Dónde vive | Nunca debe vivir |
|---|---|---|---|
| Clave privada de coordinador | Servicio coordinador | Gestor de secretos o HSM | Git, imágenes, logs, variables de frontend o tickets. |
| Clave privada de nodo | Cada nodo independiente | Gestor de secretos propio del nodo | Repositorio compartido o volumen común entre nodos. |
| Clave pública de coordinador | Nodo | Configuración versionada y autenticada | Como sustituto de autorización de acciones. |
| Clave pública de nodo | Coordinador | Registro de endpoints autenticado | Como secreto. |
| `head_hash` del ledger | Auditoría | Sistema externo de control o retención | Solo junto al mismo archivo de ledger. |

## Provisionamiento

Genera cada par una vez, fuera del repositorio. El siguiente ejemplo imprime valores que deben copiarse directamente a un gestor de secretos; no los uses como fixture ni los publiques.

```bash
python - <<'PY'
from oss_compass import generate_keypair
private_key, public_key = generate_keypair()
print(f"private={private_key}")
print(f"public={public_key}")
PY
```

Distribuye solo la clave pública al allow-list del receptor correspondiente. Configura un identificador estable de coordinador, expira credenciales en el gestor de secretos y aplica una doble firma operativa antes de reemplazar una clave confiable.

## Rotación y revocación

Primero añade la nueva clave pública a los receptores, después despliega el emisor con su clave nueva y finalmente elimina la anterior cuando todos los receipts verificados usen la huella esperada. Para revocar una clave comprometida, quítala del allow-list, corta el acceso de red del emisor y conserva los receipts, `head_hash` y evidencias de la ventana afectada para investigación.

## Límites de seguridad

Usa TLS mutuamente autenticado o una red privada autenticada alrededor de los endpoints `/v2/confirm`. Separa la operación de los tres nodos por proceso, máquina, cuenta y, cuando el riesgo lo justifique, dominio administrativo. El quórum 2-de-3 tolera la indisponibilidad o rechazo de un nodo, pero no aporta consenso bizantino ni protege contra dos nodos comprometidos.
