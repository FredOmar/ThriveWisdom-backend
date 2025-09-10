namespace ThriveWisdom.API.Configuration
{
    public class JwtSettings
    {
        // Soporte legado (una sola clave)
        public string Key { get; set; } = string.Empty;

        // Nuevo: anillo de claves
        public string? ActiveKid { get; set; }           // kid de la clave activa
        public List<JwtKey>? Keys { get; set; }          // lista de claves disponibles

        public string Issuer { get; set; } = string.Empty;
        public string Audience { get; set; } = string.Empty;

        public int ExpiresMinutes { get; set; } = 60;
        public int RefreshTokenDays { get; set; } = 7;
    }

    public class JwtKey
    {
        public string Kid { get; set; } = string.Empty;  // identificador de la clave (kid)
        public string Key { get; set; } = string.Empty;  // material de clave (secreto)
    }
}