using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using ThriveWisdom.API.DTOs.Requests;
using ThriveWisdom.API.Models;

namespace ThriveWisdom.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "Admin")]
    public class AdminController : ControllerBase
    {
        private readonly UserManager<Usuario> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AdminController(UserManager<Usuario> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        // Listado simple de usuarios
        [HttpGet("users")]
        public IActionResult ListUsers()
        {
            var list = _userManager.Users
                .Select(u => new { u.Id, u.Email, u.Nombre, u.Apellido, u.FechaCreacion })
                .ToList();
            return Ok(list);
        }

        // Ver roles de un usuario
        [HttpGet("users/{id}/roles")]
        public async Task<IActionResult> GetUserRoles(string id)
        {
            var u = await _userManager.FindByIdAsync(id);
            if (u == null) return NotFound();
            var roles = await _userManager.GetRolesAsync(u);
            return Ok(new { userId = u.Id, roles });
        }

        // Asignar rol
        [HttpPost("users/{id}/roles")]
        public async Task<IActionResult> AddRole(string id, [FromBody] AssignRoleRequest req)
        {
            var u = await _userManager.FindByIdAsync(id);
            if (u == null) return NotFound("Usuario no encontrado.");

            if (!await _roleManager.RoleExistsAsync(req.Role))
                return BadRequest("Rol inexistente.");

            var result = await _userManager.AddToRoleAsync(u, req.Role);
            if (!result.Succeeded) return BadRequest(result.Errors);

            return Ok(new { message = "Rol asignado." });
        }

        // Quitar rol
        [HttpDelete("users/{id}/roles/{role}")]
        public async Task<IActionResult> RemoveRole(string id, string role)
        {
            var u = await _userManager.FindByIdAsync(id);
            if (u == null) return NotFound("Usuario no encontrado.");

            var result = await _userManager.RemoveFromRoleAsync(u, role);
            if (!result.Succeeded) return BadRequest(result.Errors);

            return Ok(new { message = "Rol removido." });
        }
    }
}