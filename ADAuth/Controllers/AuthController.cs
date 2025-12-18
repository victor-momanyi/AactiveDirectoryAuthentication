using ADAuth.Models;
using ADAuth.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Novell.Directory.Ldap;
using System.DirectoryServices.AccountManagement;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ADAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly IJwtTokenGenerator _tokenGenerator;
        public AuthController(IConfiguration config)
        {
            _config = config;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            if (string.IsNullOrEmpty(model.Username) || string.IsNullOrEmpty(model.Password))
                return BadRequest("Username and password required");

            // Validate against Active Directory
            bool isValid = await ValidateAdCredentialsAsync(model.Username, model.Password);

            if (!isValid)
                return Unauthorized("Invalid credentials");

            // Success → generate JWT
            var token = GenerateJwtToken(model.Username);

            return Ok(new { Token = token });
        }

        [HttpPost("ADLogin")]
        public async Task<IActionResult> ADLogin([FromBody] LoginModel model)
        {
            if (string.IsNullOrEmpty(model.Username) || string.IsNullOrEmpty(model.Password))
                return BadRequest("Username and password required");

            var isValid = await ValidateAdCredentialsAsync(model.Username, model.Password);
            if (!isValid)
                return Unauthorized("Invalid credentials");

            try
            {
                var userDetails = GetUser(model.Username);

                return Ok(new { User = userDetails });
            }
            finally
            {
            }

        }

        private async Task<bool> ValidateAdCredentialsAsync(string username, string password)
        {
            var ldapSettings = _config.GetSection("LdapSettings");
            string server = ldapSettings["Server"]!;
            int port = int.Parse(ldapSettings["Port"]!);
            string domain = ldapSettings["Domain"]!;            
            LdapConnection? connection = null;

            try
            {
                connection = new LdapConnection();
                await connection.ConnectAsync(server, port);

                //Thread.Sleep(500);

                var bindAttempts = new[]
                {
                    $"{domain}\\{username}",          
                    $"{username}@{domain}.local",     
                    $"{username}@{domain}.com",       
                    $"{username}"                     
                };

                foreach (var userDn in bindAttempts)
                {
                    try
                    {
                        await connection.BindAsync(userDn, password);
                        if (connection.Bound)
                            return true;
                    }
                    catch (LdapException lex) when (lex.ResultCode == 49) // 49 = Invalid Credentials
                    {
                        // Wrong format, try next
                        continue;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                // Log ex for debugging: connection issues, network, etc.
                Console.WriteLine($"LDAP Error: {ex.Message}");
                return false;
            }
            finally
            {
                if (connection?.Connected == true)
                {
                    try { connection.Disconnect(); }
                    catch { /* ignore disconnect errors */ }
                }
            }

        }

        private async Task<(bool success, LdapConnection? connection, string? userDn)> ValidateAndBindAsync(string username, string password)
        {
            var ldapSettings = _config.GetSection("LdapSettings");
            string server = ldapSettings["Server"]!;
            int port = int.Parse(ldapSettings["Port"]!);
            string domain = ldapSettings["Domain"]!;
            string baseDn = ldapSettings["BaseDn"] ?? $"DC={domain.Replace(".", ",DC=")}";

            var connection = new LdapConnection();
            
            if (port == 636) connection.SecureSocketLayer = true;

            try
            {
                await connection.ConnectAsync(server, port);
                
                Thread.Sleep(500);

                var bindAttempts = new[]
                {
                    $"{domain}\\{username}",
                    $"{username}@{domain}.local",
                    $"{username}@{domain}.com"
                };

                foreach (var bindDn in bindAttempts)
                {
                    try
                    {
                        await connection.BindAsync(bindDn, password);
                        if (connection.Bound) break;
                    }
                    catch (LdapException) { /* Try next */ }
                }

                if (!connection.Bound) return (false, null, null);

                var searchFilter = $"(sAMAccountName={username})";
                var search = await connection.SearchAsync(baseDn, LdapConnection.ScopeSub, searchFilter, new[] { "distinguishedName" }, false);
                
                if (await search.HasMoreAsync())
                {
                    var entry = await search.NextAsync();
                    var userDn = entry.GetAttributeSet("distinguishedName").ToString();
                    return (true, connection, userDn);
                }

                return (false, null, null);
            }
            catch
            {
                return (false, null, null);
            }
        }

        private User? GetUser(string username)
        {
            var ldapSettings = _config.GetSection("LdapSettings");
            string domain = ldapSettings["Domain"]!;

            using var context = new PrincipalContext(ContextType.Domain, domain);

            var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, username);

            if (user == null)
                return null;

            return new User
            {
                UserName = user.SamAccountName,
                Name = user.DisplayName,
                Email = user.EmailAddress,
            };
        }

        private string GenerateJwtToken(string username)
        {
            var jwtSettings = _config.GetSection("JwtSettings");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("domain", _config["LdapSettings:Domain"]!)
            };

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(int.Parse(jwtSettings["ExpiryMinutes"]!)),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
  
    }
}
