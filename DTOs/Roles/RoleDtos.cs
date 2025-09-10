namespace ThriveWisdom.API.DTOs.Roles
{
    public class CreateRoleRequest
    {
        public string Name { get; set; } = default!;
    }

    public class AssignRoleRequest
    {
        public string UserId { get; set; } = default!;
        public string Role   { get; set; } = default!;
    }
}