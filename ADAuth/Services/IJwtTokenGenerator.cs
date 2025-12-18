using System.Security.Claims;

namespace ADAuth.Services
{
    public interface IJwtTokenGenerator
    {
        string GenerateToken(IEnumerable<Claim> claims);
    }
}
