using System;
using ThriveWisdom.API.Models;

namespace ThriveWisdom.API.Models
{
    public class RefreshToken
    {
        public int Id { get; set; }
        //Se inicializa para evitar CS8618
        public string Token { get; set; } = null!;
        public DateTime Expires { get; set; }
        public DateTime Created { get; set; } = DateTime.UtcNow;
        public DateTime? Revoked { get; set; }

        // FK
        public string UserId { get; set; } = null!;
        public Usuario User { get; set; }= null!;
    }
}