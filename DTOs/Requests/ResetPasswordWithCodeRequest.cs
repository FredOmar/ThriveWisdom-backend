namespace ThriveWisdom.API.DTOs.Requests
{
    public class ResetPasswordWithCodeRequest
    {
        public string Email { get; set; } = default!;
        public string Code  { get; set; } = default!;      // el código corto que llega por correo
        public string NewPassword { get; set; } = default!;
    }
}