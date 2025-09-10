using ThriveWisdom.API.DTOs.Auth;
using ThriveWisdom.API.DTOs.Requests;

namespace ThriveWisdom.API.Services.Interfaces
{
    public interface IAuthService
    {
        Task<AuthResponse?> RegisterAsync(RegisterRequest request);
        Task<AuthResponse?> LoginAsync(LoginRequest request);
        Task<AuthResponse?> RefreshAsync(string refreshToken);
        Task<bool>         LogoutAsync(string refreshToken);
        Task               RevokeAllActiveTokensAsync(string userId);

        // Email confirmation
        Task<bool> SendEmailConfirmationAsync(string email);
        Task<bool> ConfirmEmailAsync(string userId, string token);

        // Forgot / Reset password
        Task<bool> ForgotPasswordAsync(string email);
        Task<bool> ResetPasswordAsync(ResetPasswordRequest request);

        //Reset por codigo corto
        Task SendResetCodeAsync(string email); // envía el código corto por correo
        Task<bool> ResetPasswordWithCodeAsync(ResetPasswordWithCodeRequest request); // valida código y cambia password
    }
}