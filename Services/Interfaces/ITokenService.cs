using System.Security.Claims;
using ThriveWisdom.API.Models;

namespace ThriveWisdom.API.Services.Interfaces
{
    public interface ITokenService
    {
        string GenerateAccessToken(Usuario user, IEnumerable<Claim> extraClaims = null!);
        (string token, DateTime expires) GenerateRefreshToken(int days = 7);
        ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
    }
}