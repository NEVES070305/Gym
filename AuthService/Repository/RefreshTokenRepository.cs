using AuthService.Models.Refresh;
using MongoDB.Driver;
using AuthService.Repository.Interfaces;

namespace AuthService.Repository
{
    public class RefreshTokenRepository : IRefreshTokenRepository
    {
        private readonly IMongoCollection<RefreshTokenModel> _refreshTokens;

        public RefreshTokenRepository(IMongoDatabase database)
        {
            _refreshTokens = database.GetCollection<RefreshTokenModel>("refresh_tokens");

            // Configurar índice TTL para tokens expirados
            var indexOptions = new CreateIndexOptions { ExpireAfter = TimeSpan.FromSeconds(0) };
            var indexKeys = Builders<RefreshTokenModel>.IndexKeys.Ascending(rt => rt.Expiration);
            _refreshTokens.Indexes.CreateOne(new CreateIndexModel<RefreshTokenModel>(indexKeys, indexOptions));
        }

        public async Task SaveRefreshTokenAsync(RefreshTokenModel refreshTokenModel)
        {
            await _refreshTokens.InsertOneAsync(refreshTokenModel);
        }

        public async Task<RefreshTokenModel> GetRefreshTokenAsync(string userId, string refreshToken)
        {
            return await _refreshTokens
                .Find(rt => rt.UserId == userId && rt.Token == refreshToken)
                .FirstOrDefaultAsync();
        }

        public async Task RevokeRefreshTokenAsync(string userId, string refreshToken)
        {
            var filter = Builders<RefreshTokenModel>.Filter.Where(rt => rt.UserId == userId && rt.Token == refreshToken);
            var update = Builders<RefreshTokenModel>.Update.Set(rt => rt.Revoked, true);

            await _refreshTokens.UpdateOneAsync(filter, update);
        }

        public async Task RevokeAllTokensForUserAsync(string userId)
        {
            var filter = Builders<RefreshTokenModel>.Filter.Eq(rt => rt.UserId, userId);
            var update = Builders<RefreshTokenModel>.Update.Set(rt => rt.Revoked, true);

            await _refreshTokens.UpdateManyAsync(filter, update);
        }
    }
}
