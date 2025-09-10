using System.ComponentModel.DataAnnotations;

namespace ThriveWisdom.API.DTOs.Auth
{
    public class LoginRequest
    {
        [Required, EmailAddress, MaxLength(256)]
        public string Email { get; set; } = null!;

        [Required]
        public string Password { get; set; } = null!;
    }
}