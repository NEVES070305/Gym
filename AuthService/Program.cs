using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using AuthService.Repository;
using AuthService.Repository.Interfaces;
using AuthService.Business.Interfaces;
using AuthService.Business;
using AuthService.Services.Interfaces;
using AuthService.Services;
using MongoDB.Driver;

namespace AuthService
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Configuração de chave RSA para autenticação JWT
            RSA rsa = RSA.Create();
            string privateKeyPem;
            var privateKeyPath = Path.Combine(Directory.GetCurrentDirectory(), "Keys", "private_key.pem");

            if (!File.Exists(privateKeyPath))
            {
                throw new FileNotFoundException("Private key file not found.", privateKeyPath);
            }

            privateKeyPem = File.ReadAllText(privateKeyPath);
            rsa.ImportFromPem(privateKeyPem.ToCharArray());
            var signingKey = new RsaSecurityKey(rsa);

            // Registra o RsaSecurityKey como Scoped
            builder.Services.AddScoped(_ => signingKey);

            // Adicionar controladores e serviços essenciais
            builder.Services.AddControllers();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            // Configuração de autenticação JWT
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = builder.Configuration["Jwt:Issuer"],
                        ValidAudience = builder.Configuration["Jwt:Audience"],
                        IssuerSigningKey = signingKey
                    };
                });

            builder.Services.AddAuthorization();

            // Configuração de conexão com MongoDB
            var mongoConnectionString = builder.Configuration.GetConnectionString("MongoDb");
            var databaseName = builder.Configuration["DatabaseName"];

            // Registra o IMongoDatabase como Scoped
            builder.Services.AddScoped<IMongoDatabase>(sp =>
            {
                var client = new MongoClient(mongoConnectionString);
                return client.GetDatabase(databaseName);
            });

            // Registro de repositórios e serviços
            builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
            builder.Services.AddScoped<IAuthBusiness, AuthBusiness>();
            builder.Services.AddScoped<ITokenService, TokenService>();
            builder.Services.AddScoped(sp => builder.Configuration["Jwt:Issuer"]);
            builder.Services.AddScoped(sp => builder.Configuration["Jwt:Audience"]);
            var app = builder.Build();

            // Configuração do pipeline de requisição HTTP
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();
            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();
            app.Run();
        }
    }
}
