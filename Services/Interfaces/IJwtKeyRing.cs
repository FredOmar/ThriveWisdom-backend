using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;

namespace ThriveWisdom.API.Services.Interfaces
{
    public interface IJwtKeyRing
    {
        SymmetricSecurityKey ActiveKey { get; }
        IReadOnlyDictionary<string, SymmetricSecurityKey> All { get; }
        SymmetricSecurityKey? TryGet(string? kid);
    }
}