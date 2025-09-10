using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using ThriveWisdom.API.Models;

namespace ThriveWisdom.API.Data
{
    public class ApplicationDbContext : IdentityDbContext<Usuario>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options) { }

        public DbSet<RefreshToken>       RefreshTokens       { get; set; } = default!;
        public DbSet<PasswordResetCode>  PasswordResetCodes  { get; set; } = null!;

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // ===== RefreshTokens =====
            builder.Entity<RefreshToken>(e =>
            {
                e.HasKey(x => x.Id);
                e.Property(x => x.Token).IsRequired();
                e.Property(x => x.UserId).IsRequired();

                e.HasIndex(x => x.Token).IsUnique(); // único por valor
                e.HasIndex(x => x.Revoked);
                e.HasIndex(x => new { x.UserId, x.Expires });

                // a lo sumo UN token activo por usuario
                e.HasIndex(x => x.UserId)
                    .IsUnique()
                    .HasFilter("\"Revoked\" IS NULL");
            });

            // ===== PasswordResetCodes =====
            builder.Entity<PasswordResetCode>(e =>
            {
                e.HasKey(x => x.Id);

                e.HasOne(x => x.User)
                 .WithMany()
                 .HasForeignKey(x => x.UserId)
                 .OnDelete(DeleteBehavior.Cascade);

                e.Property(x => x.CodeHash).IsRequired();
                e.Property(x => x.Salt).IsRequired();

                // 1 solo código activo por usuario (no consumido y no expirado)
                e.HasIndex(x => x.UserId)
                .IsUnique()
                .HasFilter("\"Consumed\" IS NULL");

                // Índices de apoyo para consultas típicas
                e.HasIndex(x => x.Expires);
                e.HasIndex(x => new { x.UserId, x.Expires });

            });
        }
    }
}