using System;

namespace ThriveWisdom.API.Models
{
    public class PasswordResetCode
    {
        public int Id { get; set; }

        // FK al usuario
        public string UserId { get; set; } = default!;
        public Usuario User { get; set; } = default!;

        // No guardamos el código en plano
        public string CodeHash { get; set; } = default!;
        public string Salt { get; set; } = default!; // Base64

        public DateTime Expires { get; set; }
        public DateTime Created { get; set; } = DateTime.UtcNow;
        public DateTime? Consumed { get; set; }   // cuándo se use
        public int Attempts { get; set; } = 0;    // límite de intentos
    }
}