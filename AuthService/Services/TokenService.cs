using AuthService.Services.Interfaces;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using AuthService.Repository.Interfaces;

namespace AuthService.Services
{
    public class TokenService : ITokenService
    {
        private readonly RsaSecurityKey _privateKey;
        private readonly string _issuer;
        private readonly string _audience;
        private readonly IRefreshTokenRepository _refreshTokenRepository;

        public TokenService(RsaSecurityKey privateKey, string issuer, string audience, IRefreshTokenRepository refreshTokenRepository)
        {
            _privateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
            _issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
            _audience = audience ?? throw new ArgumentNullException(nameof(audience));
            _refreshTokenRepository = refreshTokenRepository ?? throw new ArgumentNullException(nameof(refreshTokenRepository));
        }

        public string GenerateAccessToken(IEnumerable<Claim> claims)
        {
            if (claims == null)
                throw new ArgumentNullException(nameof(claims));

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(30),
                SigningCredentials = new SigningCredentials(_privateKey, SecurityAlgorithms.RsaSha256),
                Issuer = _issuer,
                Audience = _audience
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);

            // Combina um GUID com os bytes randômicos para maior segurança
            return $"{Guid.NewGuid()}-{Convert.ToBase64String(randomNumber)}";
        }

        public async Task<bool> ValidateRefreshTokenAsync(string userId, string refreshToken)
        {
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentException("User ID cannot be null or empty.", nameof(userId));

            if (string.IsNullOrEmpty(refreshToken))
                throw new ArgumentException("Refresh Token cannot be null or empty.", nameof(refreshToken));

            // Busca o token no repositório de forma assíncrona
            var storedToken = await _refreshTokenRepository.GetRefreshTokenAsync(userId, refreshToken);

            // Verifica se o token existe, não está revogado e não expirou
            if (storedToken == null || storedToken.Revoked || storedToken.Expiration <= DateTime.UtcNow)
            {
                return false; // Token inválido
            }

            return true; // Token válido
        }
    }
}
