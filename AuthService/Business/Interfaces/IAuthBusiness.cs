namespace AuthService.Business.Interfaces
{
    public interface IAuthBusiness
    {
        Task<(string AccessToken, string RefreshToken)> LoginAsync(string username, string password);
        Task<(string AccessToken, string RefreshToken)> RefreshAsync(string userId, string refreshToken);
    }
}
