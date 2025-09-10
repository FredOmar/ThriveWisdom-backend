using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ThriveWisdom.API.Configuration;
using ThriveWisdom.API.Models;
using ThriveWisdom.API.Services.Interfaces;

namespace ThriveWisdom.API.Services
{
    public class TokenService : ITokenService
    {
        private readonly JwtSettings _settings;
        private readonly IJwtKeyRing _keyRing;

        public TokenService(IOptions<JwtSettings> options, IJwtKeyRing keyRing)
        {
            _settings = options.Value;
            _keyRing  = keyRing;

            // Logs amistosos para diagnósticos
            if (_settings.Keys is { Count: > 0 })
            {
                Console.WriteLine($"[JWT] Rotación habilitada. ActiveKid={_keyRing.ActiveKey.KeyId}");
                foreach (var k in _settings.Keys)
                {
                    var hash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(k.Key)));
                    Console.WriteLine($"[JWT] kid={k.Kid} hash={hash}");
                }
            }
            else
            {
                var hash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(_settings.Key)));
                Console.WriteLine($"[JWT] (legacy) kid=legacy hash={hash}");
            }
        }

        public string GenerateAccessToken(Usuario user, IEnumerable<Claim>? extraClaims = null)
        {
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub,   user.Id),
                new(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
                new(ClaimTypes.NameIdentifier,     user.Id),
                new(ClaimTypes.Name,               user.UserName ?? user.Email ?? string.Empty)
            };
            if (extraClaims != null) claims.AddRange(extraClaims);

            // Firma con la clave ACTIVA (incluye kid en el header)
            var creds = new SigningCredentials(_keyRing.ActiveKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer:  _settings.Issuer,
                audience:_settings.Audience,
                claims:  claims,
                expires: DateTime.UtcNow.AddMinutes(_settings.ExpiresMinutes),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public (string token, DateTime expires) GenerateRefreshToken(int days = 7)
        {
            var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
            var exp   = DateTime.UtcNow.AddDays(days);
            return (token, exp);
        }

        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
        {
            // OJO: la validación real se hace con IssuerSigningKeyResolver en Program.cs
            var tokenHandler = new JwtSecurityTokenHandler();

            var parameters = new TokenValidationParameters
            {
                ValidateAudience         = true,
                ValidateIssuer           = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime         = false, // permitir expirado para refresh
                ValidIssuer              = _settings.Issuer,
                ValidAudience            = _settings.Audience,

                // Fallback: usa clave activa si se invoca este helper.
                IssuerSigningKey = _keyRing.ActiveKey
            };

            try
            {
                var principal = tokenHandler.ValidateToken(token, parameters, out var securityToken);
                if (securityToken is not JwtSecurityToken jwt ||
                    !jwt.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    return null;
                }
                return principal;
            }
            catch
            {
                return null;
            }
        }
    }
}