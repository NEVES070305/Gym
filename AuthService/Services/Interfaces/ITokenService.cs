using System.Security.Claims;

namespace AuthService.Services.Interfaces
{
    public interface ITokenService
    {
        string GenerateAccessToken(IEnumerable<Claim> claims);
        string GenerateRefreshToken();
        Task<bool> ValidateRefreshTokenAsync(string userId, string refreshToken);
    }

}
