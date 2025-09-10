using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace ThriveWisdom.API.Controllers
{
    [ApiController]
    [Route("api/ping")]
    public class PingController : ControllerBase
    {
        [HttpGet("alive")]
        [AllowAnonymous]
        public IActionResult Alive() => Ok(new { ok = true, time = DateTime.UtcNow });

        [HttpGet("secure")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public IActionResult Secure()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var email = User.FindFirstValue(ClaimTypes.Email);
            return Ok(new { ok = true, userId, email });
        }
        
        [HttpGet("echo")]
        [AllowAnonymous]
        public IActionResult Echo([FromHeader(Name = "Authorization")] string? auth)
            => Ok(new { auth });
    }
}