using AuthService.Models.Refresh;

namespace AuthService.Repository.Interfaces
{
    public interface IRefreshTokenRepository
    {
       Task SaveRefreshTokenAsync(RefreshTokenModel refreshToken);
       Task RevokeRefreshTokenAsync(string userId, string refreshToken);
       Task<RefreshTokenModel> GetRefreshTokenAsync(string userId, string refreshToken);
    }
}
