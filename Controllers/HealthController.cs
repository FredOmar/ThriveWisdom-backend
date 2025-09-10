using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ThriveWisdom.API.Configuration;
using ThriveWisdom.API.Data;
using ThriveWisdom.API.Models;
using ThriveWisdom.API.Services.Interfaces;

namespace ThriveWisdom.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class HealthController : ControllerBase
    {
        private readonly ApplicationDbContext _db;
        private readonly IJwtKeyRing _keyRing;
        private readonly JwtSettings _jwt;

        public HealthController(
            ApplicationDbContext db,
            IJwtKeyRing keyRing,
            IOptions<JwtSettings> jwtOptions)
        {
            _db = db;
            _keyRing = keyRing;
            _jwt = jwtOptions.Value;
        }

        // Liveness: el proceso está arriba
        [HttpGet("live")]
        [AllowAnonymous]
        public IActionResult Live() => Ok(new { status = "ok", utc = DateTime.UtcNow });

        // Readiness: dependencias mínimas (DB)
        [HttpGet("ready")]
        [AllowAnonymous]
        public async Task<IActionResult> Ready()
        {
            bool dbOk;
            try
            {
                await _db.Database.ExecuteSqlRawAsync("SELECT 1");
                dbOk = true;
            }
            catch
            {
                dbOk = false;
            }

            var result = new
            {
                status = dbOk ? "ok" : "degraded",
                db = dbOk ? "ok" : "fail",
                utc = DateTime.UtcNow
            };
            return dbOk ? Ok(result) : StatusCode(503, result);
        }

        // Info operativa: kid activo, kids disponibles y timing
        [HttpGet("info")]
        [AllowAnonymous]
        public IActionResult Info()
        {
            var kids = _keyRing.All.Keys.ToArray();
            var active = _keyRing.ActiveKey?.KeyId ?? "legacy";

            return Ok(new
            {
                activeKid = active,
                kids,
                jwt = new
                {
                    _jwt.Issuer,
                    _jwt.Audience,
                    _jwt.ExpiresMinutes,
                    _jwt.RefreshTokenDays
                },
                utc = DateTime.UtcNow
            });
        }
    }
}