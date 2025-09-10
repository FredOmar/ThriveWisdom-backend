using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ThriveWisdom.API.Migrations
{
    /// <inheritdoc />
    public partial class AddRequirePasswordChangeToUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "RequirePasswordChange",
                table: "AspNetUsers",
                type: "boolean",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RequirePasswordChange",
                table: "AspNetUsers");
        }
    }
}
