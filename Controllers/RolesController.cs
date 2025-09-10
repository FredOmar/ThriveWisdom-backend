using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using ThriveWisdom.API.DTOs.Roles;
using ThriveWisdom.API.Models;

namespace ThriveWisdom.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "Admin")]
    public class RolesController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleMgr;
        private readonly UserManager<Usuario> _userMgr;

        public RolesController(RoleManager<IdentityRole> roleMgr, UserManager<Usuario> userMgr)
        {
            _roleMgr = roleMgr;
            _userMgr = userMgr;
        }

        [HttpGet]
        public IActionResult GetAllRoles()
        {
            var roles = _roleMgr.Roles.Select(r => r.Name).ToList();
            return Ok(new { roles });
        }

        [HttpPost]
        public async Task<IActionResult> Create([FromBody] CreateRoleRequest req)
        {
            if (string.IsNullOrWhiteSpace(req.Name)) return BadRequest("Nombre requerido.");
            if (await _roleMgr.RoleExistsAsync(req.Name)) return Conflict("Ya existe.");

            var res = await _roleMgr.CreateAsync(new IdentityRole(req.Name));
            return res.Succeeded ? Ok(new { message = "Rol creado." }) : BadRequest(res.Errors);
        }

        [HttpPost("assign")]
        public async Task<IActionResult> Assign([FromBody] AssignRoleRequest req)
        {
            var user = await _userMgr.FindByIdAsync(req.UserId);
            if (user == null) return NotFound("Usuario no encontrado.");
            if (!await _roleMgr.RoleExistsAsync(req.Role)) return NotFound("Rol no existe.");

            var res = await _userMgr.AddToRoleAsync(user, req.Role);
            return res.Succeeded ? Ok(new { message = "Rol asignado." }) : BadRequest(res.Errors);
        }
    }
}