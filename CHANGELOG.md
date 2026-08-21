# Changelog

Todos los cambios relevantes de OSS Compass se documentarán aquí.

## [0.1.0] - 2026-08-16

### Añadido

- Sobres de validación PVC-U con hash de payload y resultados codificados.
- Regla declarativa de campos obligatorios.
- Confirmación distribuida con tres nodos y quórum configurable, 2-de-3 por defecto.
- CLI de auditoría de preparación open source.
- Pruebas automatizadas y workflow de integración continua.

## [0.2.0] - 2026-08-18

### Añadido

- `NodeServer` HTTP para validación en procesos independientes.
- `NodeConfig` y `confirm_over_network` con quórum 2-de-3.
- Firmas HMAC-SHA256 de solicitudes y respuestas.
- Nonce anti-replay, ventana temporal, verificación de destino y registro de fallos de nodo.
- Pruebas de integración para 3-de-3, divergencia, caída, firma inválida y replay.

### Nota de seguridad

El transporte de desarrollo usa HTTP local. Producción debe usar TLS, secretos externos y tres procesos o máquinas independientes.

## [0.6.0] - 2026-08-21

### Añadido

- Workflow de OpenSSF Scorecard con resultados SARIF y publicación de evidencia.
- Badge de Scorecard en el README.
- Alertas de vulnerabilidades y actualizaciones de seguridad de Dependabot activadas en GitHub.
- Metadatos de paquete actualizados para reflejar la confirmación HTTP firmada de tres nodos.
