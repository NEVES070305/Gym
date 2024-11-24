using AuthService.Business.Interfaces;
using AuthService.Services.Interfaces;
using AuthService.Repository.Interfaces;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using AuthService.Models.Refresh;

namespace AuthService.Business
{
    public class AuthBusiness : IAuthBusiness
    {
        private readonly ITokenService _tokenService;
        private readonly IRefreshTokenRepository _refreshTokenRepository;

        public AuthBusiness(ITokenService tokenService, IRefreshTokenRepository refreshTokenRepository)
        {
            _tokenService = tokenService ?? throw new ArgumentNullException(nameof(tokenService));
            _refreshTokenRepository = refreshTokenRepository ?? throw new ArgumentNullException(nameof(refreshTokenRepository));
        }

        public async Task<(string AccessToken, string RefreshToken)> LoginAsync(string username, string password)
        {
            ValidateCredentials(username, password);

            var claims = GenerateUserClaims(username);

            // Gerar tokens
            var accessToken = _tokenService.GenerateAccessToken(claims);
            var refreshToken = _tokenService.GenerateRefreshToken();

            // Criar e salvar o modelo de Refresh Token
            var refreshTokenModel = CreateRefreshTokenModel(username, refreshToken);
            await _refreshTokenRepository.SaveRefreshTokenAsync(refreshTokenModel);

            return (accessToken, refreshToken);
        }

        public async Task<(string AccessToken, string RefreshToken)> RefreshAsync(string userId, string refreshToken)
        {
            // Validação delegada ao TokenService
            var isValid = await _tokenService.ValidateRefreshTokenAsync(userId, refreshToken);
            if (!isValid)
            {
                throw new UnauthorizedAccessException("Invalid or expired refresh token.");
            }

            var claims = GenerateUserClaims(userId);

            // Gerar novo Access Token e Refresh Token
            var newAccessToken = _tokenService.GenerateAccessToken(claims);
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            // Atualizar o Refresh Token no repositório
            await SaveNewRefreshToken(userId, newRefreshToken);

            // Revogar o Refresh Token antigo
            await _refreshTokenRepository.RevokeRefreshTokenAsync(userId, refreshToken);

            return (newAccessToken, newRefreshToken);
        }

        private void ValidateCredentials(string username, string password)
        {
            if (username != "testuser" || password != "testpassword")
            {
                throw new UnauthorizedAccessException("Invalid credentials");
            }
        }

        private IEnumerable<Claim> GenerateUserClaims(string userId)
        {
            return new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Role, "User")
            };
        }

        private RefreshTokenModel CreateRefreshTokenModel(string userId, string refreshToken)
        {
            return new RefreshTokenModel
            {
                UserId = userId,
                Token = refreshToken,
                Expiration = DateTime.UtcNow.AddDays(7)
            };
        }

        private async Task SaveNewRefreshToken(string userId, string newRefreshToken)
        {
            var newRefreshTokenModel = CreateRefreshTokenModel(userId, newRefreshToken);
            await _refreshTokenRepository.SaveRefreshTokenAsync(newRefreshTokenModel);
        }
    }
}
