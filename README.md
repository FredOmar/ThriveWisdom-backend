# ThriveWisdom API (.NET 9)

API de autenticación con **JWT (key ring)**, **roles**, **refresh tokens** (1 activo por usuario con índice parcial), **reset por código corto**, **rate limiting**, **CORS** y **headers de seguridad**. Lista para usarse como base de microservicio o backend para apps móviles/web.

## Requisitos
- .NET 9 SDK
- Docker Desktop (para Postgres en contenedor)
- (Opcional) MailHog/SMTP4Dev para correo en dev

## Configuración

1. Copia `.env.example` → `.env` y completa tus valores  
   > No subas `.env` al repo.

2. (Alternativa) `dotnet user-secrets`:
```bash
cd ThriveWisdom.API
dotnet user-secrets init
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Host=localhost;Port=5432;Database=thrivewisdom;Username=postgres;Password=..."
dotnet user-secrets set "Jwt:ActiveKid" "k3"
dotnet user-secrets set "Jwt:Keys:0:Kid" "k3"
dotnet user-secrets set "Jwt:Keys:0:Key" "TU_SECRETO_LARGO"
