using Microsoft.AspNetCore.Identity;

namespace ThriveWisdom.API.Models
{
    public class Usuario : IdentityUser
    {
        public string Nombre { get; set; } = string.Empty;
        public string Apellido { get; set; } = string.Empty;
        public DateTime FechaCreacion { get; set; } = DateTime.UtcNow;

        // 👇 Nuevo: si es true, el login queda bloqueado hasta hacer reset de password
        public bool RequirePasswordChange { get; set; } = false;
    }
}