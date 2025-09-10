namespace ThriveWisdom.API.DTOs.Auth
{
    public class ResetPasswordRequest
    {
        public string UserId { get; set; } = string.Empty;
        public string Token { get; set; } = string.Empty;      // token de reset (desde el correo)
        public string NewPassword { get; set; } = string.Empty; // nueva contraseña
    }
}