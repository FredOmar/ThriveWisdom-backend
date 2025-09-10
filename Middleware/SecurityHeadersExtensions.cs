using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace ThriveWisdom.API.Middleware
{
    public static class SecurityHeadersExtensions
    {
        public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app, IWebHostEnvironment env)
        {
            // Cabeceras seguras para cualquier respuesta
            app.Use(async (ctx, next) =>
            {
                // Nunca adivines tipos
                ctx.Response.Headers[HeaderNames.XContentTypeOptions] = "nosniff";

                // No permitir iframes
                ctx.Response.Headers["X-Frame-Options"] = "DENY";

                // Política de referencia mínima
                ctx.Response.Headers["Referrer-Policy"] = "no-referrer";

                // Política de permisos (solo ejemplo, vacío por ahora)
                ctx.Response.Headers["Permissions-Policy"] = "interest-cohort=()";

                // No caches en endpoints sensibles (Auth)
                if (ctx.Request.Path.StartsWithSegments("/api/auth"))
                {
                    ctx.Response.Headers[HeaderNames.CacheControl] = "no-store";
                    ctx.Response.Headers[HeaderNames.Pragma] = "no-cache";
                }

                // CSP estricta SOLO en producción (para no romper Swagger en dev)
                if (env.IsProduction())
                {
                    // Como es API, bloqueamos todo y negamos ser embebidos
                    // (Si alguna vez sirves archivos estáticos, adapta esta CSP)
                    ctx.Response.Headers["Content-Security-Policy"] =
                        "default-src 'none'; base-uri 'none'; frame-ancestors 'none';";
                    ctx.Response.Headers["Cross-Origin-Opener-Policy"] = "same-origin";
                }

                await next();
            });

            return app;
        }
    }
}