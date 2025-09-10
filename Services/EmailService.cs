using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;
using ThriveWisdom.API.Services.Interfaces;

namespace ThriveWisdom.API.Services
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _cfg;
        public EmailService(IConfiguration cfg) => _cfg = cfg;

        public async Task SendAsync(string to, string subject, string htmlBody)
        {
            var host = _cfg["Smtp:Host"]!;
            var port = int.Parse(_cfg["Smtp:Port"] ?? "25");
            var user = _cfg["Smtp:User"];
            var pass = _cfg["Smtp:Pass"];
            var from = _cfg["Smtp:From"] ?? "no-reply@local";

            using var msg = new MailMessage(from, to) { Subject = subject, Body = htmlBody, IsBodyHtml = true };
            using var smtp = new SmtpClient(host, port)
            {
                EnableSsl = false,
                Credentials = (string.IsNullOrEmpty(user) ? null : new NetworkCredential(user, pass))
            };
            await smtp.SendMailAsync(msg);
        }
    }
}