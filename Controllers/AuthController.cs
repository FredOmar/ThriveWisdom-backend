using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;   // 👈
using ThriveWisdom.API.DTOs.Auth;
using ThriveWisdom.API.DTOs.Requests;
using ThriveWisdom.API.Models;
using ThriveWisdom.API.Services.Interfaces;

namespace ThriveWisdom.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _auth;
        private readonly UserManager<Usuario> _userManager;

        public AuthController(IAuthService auth, UserManager<Usuario> userManager)
        {
            _auth = auth;
            _userManager = userManager;
        }

        [HttpPost("register")]
        [AllowAnonymous]
        [EnableRateLimiting("auth")]  // 👈
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            var res = await _auth.RegisterAsync(request);
            if (res == null) return BadRequest("No se pudo registrar.");
            return Ok(res);
        }

        [HttpPost("login")]
        [AllowAnonymous]
        [EnableRateLimiting("auth")] 
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null) return Unauthorized("Credenciales inválidas.");

            if (!await _userManager.IsEmailConfirmedAsync(user))
                return StatusCode(403, new { message = "Debes confirmar tu correo." });

            if (user.RequirePasswordChange)
                return StatusCode(423, new { message = "Debes restablecer tu contraseña." });

            var res = await _auth.LoginAsync(request);
            if (res == null) return Unauthorized("Credenciales inválidas.");
            return Ok(res);
        }

        [HttpPost("refresh")]
        [AllowAnonymous]
        [EnableRateLimiting("auth")] 
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest req)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            var res = await _auth.RefreshAsync(req.RefreshToken);
            if (res == null) return Unauthorized("Refresh token inválido o expirado.");
            return Ok(res);
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] RefreshTokenRequest req)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            var ok = await _auth.LogoutAsync(req.RefreshToken);
            if (!ok) return BadRequest("No se pudo cerrar sesión.");
            return Ok(new { message = "Sesión cerrada." });
        }

        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> Me()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId)) return Unauthorized();
            var u = await _userManager.FindByIdAsync(userId);
            if (u == null) return NotFound();

            var roles = await _userManager.GetRolesAsync(u);
            return Ok(new { u.Id, u.Email, u.Nombre, u.Apellido, u.FechaCreacion, roles });
        }

        // ---------- Email confirmation ----------
        [HttpPost("send-confirmation")]
        [AllowAnonymous]
        [EnableRateLimiting("auth")]  // limitar spam de envíos
        public async Task<IActionResult> SendConfirmation([FromQuery] string emailAddress)
        {
            await _auth.SendEmailConfirmationAsync(emailAddress);
            return Ok(new { message = "Correo de confirmación enviado." });
        }

        [HttpGet("confirm-email")]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string token)
        {
            var ok = await _auth.ConfirmEmailAsync(userId, token);
            if (!ok) return BadRequest(new { message = "Token inválido." });
            return Ok(new { message = "Correo confirmado. Ya puedes iniciar sesión." });
        }

        // ---------- Forgot / Reset ----------
        [HttpPost("forgot-password")]
        [AllowAnonymous]
        [EnableRateLimiting("auth")]  
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest req)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            await _auth.ForgotPasswordAsync(req.Email);
            return Ok(new { message = "Si el correo existe, enviaremos instrucciones de restablecimiento." });
        }

        [HttpPost("send-reset-code")]
        [AllowAnonymous]
        [EnableRateLimiting("auth")]  
        public async Task<IActionResult> SendResetCode([FromQuery] string email)
        {
            await _auth.SendResetCodeAsync(email);
            return Ok(new { message = "Código enviado (si el correo existe)." });
        }

        [HttpPost("reset-password")]
        [AllowAnonymous]
        [EnableRateLimiting("auth")]  // 👈
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordWithCodeRequest request)
        {
            var ok = await _auth.ResetPasswordWithCodeAsync(request);
            if (!ok) return BadRequest(new { message = "Código inválido/expirado o contraseña no cumple política." });
            return Ok(new { message = "Contraseña actualizada. Ya puedes iniciar sesión." });
        }
    }
}