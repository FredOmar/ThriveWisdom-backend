using System.ComponentModel.DataAnnotations;

namespace ThriveWisdom.API.DTOs.Auth
{
    public class RegisterRequest
    {
        [Required, EmailAddress, MaxLength(256)]
        public string Email { get; set; } = null!;

        [Required, MinLength(8)]
        public string Password { get; set; } = null!;

        [Required, MaxLength(100)]
        public string Nombre { get; set; } = null!;

        [Required, MaxLength(100)]
        public string Apellido { get; set; } = null!;
    }
}