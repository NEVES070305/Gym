using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Bson;

namespace AuthService.Models.Refresh
{
    public class RefreshTokenModel
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }

        public string UserId { get; set; } 
        public string Token { get; set; } 
        public DateTime Expiration { get; set; } 
        public bool Revoked { get; set; } = false; 
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow; 
    }
}
