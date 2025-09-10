using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ThriveWisdom.API.Configuration;
using ThriveWisdom.API.Data;
using ThriveWisdom.API.DTOs.Auth;
using ThriveWisdom.API.DTOs.Requests;
using ThriveWisdom.API.Models;
using ThriveWisdom.API.Services.Interfaces;

namespace ThriveWisdom.API.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<Usuario> _userManager;
        private readonly SignInManager<Usuario> _signInManager;
        private readonly ApplicationDbContext _db;
        private readonly ITokenService _tokenService;
        private readonly IEmailService _email;
        private readonly JwtSettings _jwt;

        public AuthService(
            UserManager<Usuario> userManager,
            SignInManager<Usuario> signInManager,
            ApplicationDbContext db,
            ITokenService tokenService,
            IEmailService email,
            IOptions<JwtSettings> jwtOptions)
        {
            _userManager   = userManager;
            _signInManager = signInManager;
            _db            = db;
            _tokenService  = tokenService;
            _email         = email;
            _jwt           = jwtOptions.Value;
        }

        // ---------------- helpers ----------------
        private static string DecodeToken(string token)
        {
            var decoded = WebUtility.UrlDecode(token ?? string.Empty) ?? string.Empty;
            return decoded.Replace(" ", "+");
        }

        private static string GenerateFriendlyCode(int length)
        {
            const string lower   = "abcdefghijkmnopqrstuvwxyz"; // sin l
            const string upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ";  // sin I, O
            const string symbols = "+-*/@¡!";
            string all = lower + upper + symbols;

            Span<char> code = stackalloc char[length];
            code[0] = lower[RandomNumberGenerator.GetInt32(lower.Length)];
            code[1] = upper[RandomNumberGenerator.GetInt32(upper.Length)];
            code[2] = symbols[RandomNumberGenerator.GetInt32(symbols.Length)];
            for (int i = 3; i < length; i++)
                code[i] = all[RandomNumberGenerator.GetInt32(all.Length)];
            for (int i = code.Length - 1; i > 0; i--)
            {
                int j = RandomNumberGenerator.GetInt32(i + 1);
                (code[i], code[j]) = (code[j], code[i]);
            }
            return new string(code);
        }

        private static string HashCodeWithSalt(string code, byte[] salt)
        {
            using var hmac = new HMACSHA256(salt);
            return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(code)));
        }

        private static bool FixedTimeEquals(string aB64, string bB64)
        {
            var a = Convert.FromBase64String(aB64);
            var b = Convert.FromBase64String(bB64);
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
        // -----------------------------------------

        public async Task<AuthResponse?> RegisterAsync(RegisterRequest request)
        {
            var exists = await _userManager.FindByEmailAsync(request.Email);
            if (exists != null) return null;

            var user = new Usuario
            {
                UserName       = request.Email,
                Email          = request.Email,
                Nombre         = request.Nombre ?? "",
                Apellido       = request.Apellido ?? "",
                FechaCreacion  = DateTime.UtcNow,
                EmailConfirmed = false
            };
            var create = await _userManager.CreateAsync(user, request.Password);
            if (!create.Succeeded) return null;

            return new AuthResponse
            {
                UserId   = user.Id,
                Email    = user.Email!,
                Nombre   = user.Nombre,
                Apellido = user.Apellido
            };
        }

        public async Task<AuthResponse?> LoginAsync(LoginRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null) return null;
            if (!user.EmailConfirmed) return null;
            if (user.RequirePasswordChange) return null;

            var check = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
            if (!check.Succeeded) return null;

            await using var tx = await _db.Database.BeginTransactionAsync();

            // 1) Revoca cualquier refresh ACTIVO (único por índice parcial)
            await _db.RefreshTokens
                .Where(x => x.UserId == user.Id && x.Revoked == null && x.Expires > DateTime.UtcNow)
                .ExecuteUpdateAsync(s => s.SetProperty(p => p.Revoked, DateTime.UtcNow));

            // 2) Genera tokens
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = roles.Select(r => new Claim(ClaimTypes.Role, r));
            var access = _tokenService.GenerateAccessToken(user, roleClaims);
            var (refresh, exp) = _tokenService.GenerateRefreshToken(_jwt.RefreshTokenDays);

            // 3) Inserta el nuevo refresh
            _db.RefreshTokens.Add(new RefreshToken
            {
                Token   = refresh,
                Expires = exp,
                Created = DateTime.UtcNow,
                UserId  = user.Id
            });

            // 4) Guarda UNA sola vez y confirma
            await _db.SaveChangesAsync();
            await tx.CommitAsync();

            return new AuthResponse
            {
                AccessToken  = access,
                RefreshToken = refresh,
                UserId       = user.Id,
                Email        = user.Email!,
                Nombre       = user.Nombre,
                Apellido     = user.Apellido
            };
        }


        public async Task<AuthResponse?> RefreshAsync(string refreshToken)
        {
            var rt = await _db.RefreshTokens.Include(x => x.User)
                        .FirstOrDefaultAsync(x => x.Token == refreshToken);
            if (rt == null || rt.Revoked != null || rt.Expires <= DateTime.UtcNow) return null;

            var user = rt.User!;
            if (user.RequirePasswordChange) return null;

            await using var tx = await _db.Database.BeginTransactionAsync();

            // 1) Revoca el refresh usado
            rt.Revoked = DateTime.UtcNow;

            // 2) Re-emite tokens
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = roles.Select(r => new Claim(ClaimTypes.Role, r));
            var access = _tokenService.GenerateAccessToken(user, roleClaims);
            var (newRefresh, exp) = _tokenService.GenerateRefreshToken(_jwt.RefreshTokenDays);

            // 3) Inserta el nuevo refresh
            _db.RefreshTokens.Add(new RefreshToken
            {
                Token   = newRefresh,
                Expires = exp,
                Created = DateTime.UtcNow,
                UserId  = user.Id
            });

            // 4) Guarda y commit (una sola vez)
            await _db.SaveChangesAsync();
            await tx.CommitAsync();

            return new AuthResponse
            {
                AccessToken  = access,
                RefreshToken = newRefresh,
                UserId       = user.Id,
                Email        = user.Email!,
                Nombre       = user.Nombre,
                Apellido     = user.Apellido
            };
        }

        public async Task<bool> LogoutAsync(string refreshToken)
        {
            var rt = await _db.RefreshTokens.FirstOrDefaultAsync(x => x.Token == refreshToken);
            if (rt == null || rt.Revoked != null) return false;
            rt.Revoked = DateTime.UtcNow;
            await _db.SaveChangesAsync();
            return true;
        }

        public async Task RevokeAllActiveTokensAsync(string userId)
        {
            await _db.RefreshTokens
                .Where(x => x.UserId == userId && x.Revoked == null && x.Expires > DateTime.UtcNow)
                .ExecuteUpdateAsync(s => s.SetProperty(t => t.Revoked, DateTime.UtcNow));
            // Nota: no hace falta SaveChanges aquí si este método se llama
            // dentro de otro flujo que luego guarda. Si lo usas aislado, está OK así.
        }


        // ----- Email confirmation -----
        public async Task<bool> SendEmailConfirmationAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) return true;

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var link  = $"http://localhost:5106/api/auth/confirm-email?userId={WebUtility.UrlEncode(user.Id)}&token={WebUtility.UrlEncode(token)}";

            var html = $@"<p>Hola {WebUtility.HtmlEncode(user.Nombre)},</p>
                          <p>Confirma tu correo: <a href=""{link}"">Confirmar</a></p>";
            await _email.SendAsync(user.Email!, "Confirma tu correo", html);
            return true;
        }

        public async Task<bool> ConfirmEmailAsync(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return false;
            var decoded = DecodeToken(token);
            var result  = await _userManager.ConfirmEmailAsync(user, decoded);
            return result.Succeeded;
        }

        // ----- Forgot / Reset (token largo, por compatibilidad) -----
        public async Task<bool> ForgotPasswordAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) return true;

            user.RequirePasswordChange = true;
            await _userManager.UpdateAsync(user);
            await RevokeAllActiveTokensAsync(user.Id);

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var html = $@"<p>Hola {WebUtility.HtmlEncode(user.Nombre)},</p>
                          <p>Token de restablecimiento (pégalo en la app):</p>
                          <pre>{WebUtility.HtmlEncode(token)}</pre>";
            await _email.SendAsync(user.Email!, "Restablecer contraseña", html);
            return true;
        }

        public async Task<bool> ResetPasswordAsync(ResetPasswordRequest request)
        {
            var user = await _userManager.FindByIdAsync(request.UserId);
            if (user == null) return false;

            var decoded = DecodeToken(request.Token);
            var result  = await _userManager.ResetPasswordAsync(user, decoded, request.NewPassword);
            if (!result.Succeeded) return false;

            user.RequirePasswordChange = false;
            await _userManager.UpdateSecurityStampAsync(user);
            await _userManager.UpdateAsync(user);
            await RevokeAllActiveTokensAsync(user.Id);
            return true;
        }

        // =============== RESET POR CÓDIGO CORTO ===============
        public async Task SendResetCodeAsync(string email)
        {
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null) return; // no revelar existencia

            // Invalida código activo previo
            var existing = await _db.PasswordResetCodes
                .FirstOrDefaultAsync(c => c.UserId == user.Id && c.Consumed == null && c.Expires > DateTime.UtcNow);
            if (existing != null)
            {
                existing.Consumed = DateTime.UtcNow;
                await _db.SaveChangesAsync();
            }

            var code     = GenerateFriendlyCode(8);
            var salt     = RandomNumberGenerator.GetBytes(16);
            var codeHash = HashCodeWithSalt(code, salt);

            _db.PasswordResetCodes.Add(new PasswordResetCode
            {
                UserId   = user.Id,
                CodeHash = codeHash,
                Salt     = Convert.ToBase64String(salt),
                Expires  = DateTime.UtcNow.AddMinutes(10)
            });
            await _db.SaveChangesAsync();

            var subject = "Código para restablecer contraseña";
            var body    = $"Hola {user.Nombre ?? user.Email},\n\n" +
                          $"Usa este código (expira en 10 minutos): {code}\n\n" +
                          $"Si no solicitaste esto, ignora el mensaje.";
            await _email.SendAsync(user.Email!, subject, body);
        }

        public async Task<bool> ResetPasswordWithCodeAsync(ResetPasswordWithCodeRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null) return false;

            var row = await _db.PasswordResetCodes
                .FirstOrDefaultAsync(c => c.UserId == user.Id && c.Consumed == null && c.Expires > DateTime.UtcNow);
            if (row == null) return false;

            if (row.Attempts >= 5)
            {
                row.Consumed = DateTime.UtcNow; // bloquea este código
                await _db.SaveChangesAsync();
                return false;
            }

            row.Attempts++;

            var saltBytes    = Convert.FromBase64String(row.Salt);
            var incomingHash = HashCodeWithSalt(request.Code, saltBytes);

            if (!FixedTimeEquals(incomingHash, row.CodeHash))
            {
                await _db.SaveChangesAsync(); // persiste Attempts++
                return false;
            }

            var token  = await _userManager.GeneratePasswordResetTokenAsync(user);
            var result = await _userManager.ResetPasswordAsync(user, token, request.NewPassword);
            if (!result.Succeeded)
            {
                await _db.SaveChangesAsync();
                return false;
            }

            row.Consumed = DateTime.UtcNow;
            user.RequirePasswordChange = false;
            await _userManager.UpdateSecurityStampAsync(user);
            await _userManager.UpdateAsync(user);
            await RevokeAllActiveTokensAsync(user.Id);
            await _db.SaveChangesAsync();

            return true;
        }
    }
}