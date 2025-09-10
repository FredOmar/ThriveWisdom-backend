using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Security.Claims;
using System.Threading.RateLimiting;

using ThriveWisdom.API.Configuration;
using ThriveWisdom.API.Data;
using ThriveWisdom.API.Models;
using ThriveWisdom.API.Services;
using ThriveWisdom.API.Services.Interfaces;

var builder = WebApplication.CreateBuilder(args);

// -----------------------------------------------------
// 0) Configuración JwtSettings (desde appsettings + env + user-secrets)
// -----------------------------------------------------
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));
var jwt = builder.Configuration.GetSection("Jwt").Get<JwtSettings>()
          ?? throw new InvalidOperationException("Missing Jwt section");

if (string.IsNullOrWhiteSpace(jwt.Issuer))   throw new InvalidOperationException("Missing Jwt:Issuer");
if (string.IsNullOrWhiteSpace(jwt.Audience)) throw new InvalidOperationException("Missing Jwt:Audience");

// Key Ring (rotación)
var keyRing = new JwtKeyRing(jwt);
builder.Services.AddSingleton<IJwtKeyRing>(keyRing);

// Logging mínimo sobre el estado de claves (no imprime la clave)
if (jwt.Keys is { Count: > 0 })
{
    Console.WriteLine($"[JWT] validation: claves = {string.Join(", ", keyRing.All.Keys)} (activa={keyRing.ActiveKey.KeyId})");
}
else
{
    Console.WriteLine("[JWT] validation: modo legacy (kid=legacy)");
}

// -----------------------------------------------------
// 1) DB + Identity (ConnectionString desde env/user-secrets)
// -----------------------------------------------------
var connStr = builder.Configuration.GetConnectionString("DefaultConnection");
if (string.IsNullOrWhiteSpace(connStr))
    throw new InvalidOperationException("ConnectionStrings:DefaultConnection no está configurado (usa env o user-secrets).");

builder.Services.AddDbContext<ApplicationDbContext>(opts =>
    opts.UseNpgsql(connStr));

builder.Services.AddIdentity<Usuario, IdentityRole>(opts =>
{
    opts.SignIn.RequireConfirmedEmail = true;
    opts.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Password/lockout extras
builder.Services.Configure<IdentityOptions>(o =>
{
    o.Password.RequireDigit = true;
    o.Password.RequireLowercase = true;
    o.Password.RequireUppercase = true;
    o.Password.RequireNonAlphanumeric = false;
    o.Password.RequiredLength = 8;

    o.Lockout.MaxFailedAccessAttempts = 5;
    o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    o.User.RequireUniqueEmail = true;
});

// -----------------------------------------------------
// 2) CORS (allow-list configurable)
// -----------------------------------------------------
var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
                     ?? new[] { "http://localhost:5173" };

builder.Services.AddCors(opt =>
{
    opt.AddPolicy("Frontend", p =>
        p.WithOrigins(allowedOrigins)
         .AllowAnyHeader()
         .AllowAnyMethod()
         .AllowCredentials());
});

// -----------------------------------------------------
// 3) Rate limiting (solo login y send-reset-code)
// -----------------------------------------------------
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.AddPolicy("auth", httpContext =>
    {
        var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: ip,
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true
            }
        );
    });
});

// -----------------------------------------------------
// 4) JWT Auth (resolver por kid con KeyRing)
// -----------------------------------------------------
builder.Services.AddAuthentication(o =>
{
    o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    // En producción no exponemos detalles
    options.IncludeErrorDetails = builder.Environment.IsDevelopment();

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,

        ValidIssuer = jwt.Issuer,
        ValidAudience = jwt.Audience,
        ClockSkew = TimeSpan.Zero,

        IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
        {
            var k = keyRing.TryGet(kid);
            if (k != null) return new[] { k };
            return keyRing.All.Values; // fallback durante rotación
        }
    };

    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = ctx =>
        {
            var auth = ctx.Request.Headers["Authorization"].ToString();
            if (!string.IsNullOrEmpty(auth) && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                ctx.Token = auth["Bearer ".Length..].Trim();
            return Task.CompletedTask;
        },
        OnTokenValidated = ctx =>
        {
            if (builder.Environment.IsDevelopment() &&
                ctx.SecurityToken is System.IdentityModel.Tokens.Jwt.JwtSecurityToken jwtTok)
            {
                Console.WriteLine($"[JWT] OK kid={jwtTok.Header.Kid} sub={ctx.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value}");
            }
            return Task.CompletedTask;
        },
        OnAuthenticationFailed = ctx =>
        {
            Console.WriteLine("[JWT] FAIL " + ctx.Exception.Message);
            return Task.CompletedTask;
        }
    };
});

// -----------------------------------------------------
// 5) Servicios App
// -----------------------------------------------------
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IAuthService, AuthService>();

// -----------------------------------------------------
// 6) Controllers + Swagger (UI solo en Development)
// -----------------------------------------------------
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "ThriveWisdom API", Version = "v1" });
    c.CustomSchemaIds(t => t.FullName);

    var jwtScheme = new OpenApiSecurityScheme
    {
        Scheme = "bearer",
        BearerFormat = "JWT",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Description = "Pega tu token (sin 'Bearer').",
        Reference = new OpenApiReference
        {
            Id = JwtBearerDefaults.AuthenticationScheme,
            Type = ReferenceType.SecurityScheme
        }
    };
    c.AddSecurityDefinition(jwtScheme.Reference.Id, jwtScheme);
    c.AddSecurityRequirement(new OpenApiSecurityRequirement { { jwtScheme, Array.Empty<string>() } });
});

var app = builder.Build();

// -----------------------------------------------------
// 7) Pipeline
// -----------------------------------------------------
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
else
{
    // HSTS solo prod (puedes controlarlo con config Security:EnableHsts true/false)
    app.UseHsts();

    // CSP + cabeceras reforzadas SOLO en producción
    app.Use(async (ctx, next) =>
    {
        ctx.Response.Headers["X-Frame-Options"] = "DENY";
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
        ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
        ctx.Response.Headers["Permissions-Policy"] = "interest-cohort=()";

        // API (sin HTML): política estricta
        ctx.Response.Headers["Content-Security-Policy"] =
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; img-src 'self' data:;";

        await next();
    });
}

// En dev mantenemos cabeceras básicas
if (app.Environment.IsDevelopment())
{
    app.Use(async (ctx, next) =>
    {
        ctx.Response.Headers["X-Frame-Options"] = "DENY";
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
        ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
        ctx.Response.Headers["Permissions-Policy"] = "interest-cohort=()";
        await next();
    });
}

app.UseHttpsRedirection();
app.UseCors("Frontend");
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// -----------------------------------------------------
// 8) Seed de roles/usuario admin
// -----------------------------------------------------
async Task SeedAsync(WebApplication app)
{
    using var scope = app.Services.CreateScope();
    var roleMgr = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<Usuario>>();

    string[] roles = ["Admin", "User"];
    foreach (var r in roles)
        if (!await roleMgr.RoleExistsAsync(r))
            await roleMgr.CreateAsync(new IdentityRole(r));

    var adminEmail = "admin@thrive.local";
    var admin = await userMgr.FindByEmailAsync(adminEmail);
    if (admin == null)
    {
        admin = new Usuario
        {
            UserName = adminEmail,
            Email = adminEmail,
            EmailConfirmed = true,
            Nombre = "Admin",
            Apellido = "Root",
            FechaCreacion = DateTime.UtcNow
        };
        await userMgr.CreateAsync(admin, "Admin123$");
        await userMgr.AddToRoleAsync(admin, "Admin");
    }
}

await SeedAsync(app);

app.Run();
