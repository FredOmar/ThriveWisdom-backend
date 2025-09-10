using System.Text;
using Microsoft.IdentityModel.Tokens;
using ThriveWisdom.API.Configuration;
using ThriveWisdom.API.Services.Interfaces;

namespace ThriveWisdom.API.Services
{
    public class JwtKeyRing : IJwtKeyRing
    {
        private readonly Dictionary<string, SymmetricSecurityKey> _keys = new();

        public SymmetricSecurityKey ActiveKey { get; }
        public IReadOnlyDictionary<string, SymmetricSecurityKey> All => _keys;

        public JwtKeyRing(JwtSettings jwt)
        {
            // Si vienen Keys => modo rotación; si no, modo legado con Jwt:Key
            if (jwt.Keys is { Count: > 0 })
            {
                foreach (var k in jwt.Keys)
                {
                    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(k.Key))
                    {
                        KeyId = k.Kid
                    };
                    _keys[k.Kid] = key;
                }

                var activeKid = !string.IsNullOrWhiteSpace(jwt.ActiveKid)
                    ? jwt.ActiveKid!
                    : jwt.Keys.First().Kid;

                if (!_keys.TryGetValue(activeKid, out var active))
                    throw new InvalidOperationException($"ActiveKid '{activeKid}' no existe en Jwt:Keys.");

                ActiveKey = active;
            }
            else
            {
                // Legado: una sola key
                var legacyKid = "legacy";
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Key))
                {
                    KeyId = legacyKid
                };
                _keys[legacyKid] = key;
                ActiveKey = key;
            }
        }

        public SymmetricSecurityKey? TryGet(string? kid)
            => !string.IsNullOrWhiteSpace(kid) && _keys.TryGetValue(kid!, out var k) ? k : null;
    }
}