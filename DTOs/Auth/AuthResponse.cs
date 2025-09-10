namespace ThriveWisdom.API.DTOs.Auth
{
    public class AuthResponse
    {
        public string AccessToken  { get; set; } = null!;
        public string RefreshToken { get; set; } = null!;
        public string UserId       { get; set; } = null!;
        public string Email        { get; set; } = null!;
        public string Nombre       { get; set; } = "";
        public string Apellido     { get; set; } = "";
    }
}