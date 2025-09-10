# Seguridad

- No subir secretos (`.env`, user-secrets).
- Habilitar en GitHub:
  - Secret scanning + Push protection
  - Dependabot alerts & security updates
  - CodeQL code scanning
- Rotación de claves JWT vía key ring.
- Índice parcial en RefreshTokens garantiza 1 refresh activo por usuario.
