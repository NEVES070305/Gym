using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using AuthService.Models;
using System.Text;
using System.IdentityModel.Tokens.Jwt;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly RsaSecurityKey _privateKey;
    private readonly RsaSecurityKey _publicKey;
    private readonly string _issuer;
    private readonly string _audience;

    public AuthController(IConfiguration configuration)
    {
        // Carregar as configurações do appsettings.json
        _issuer = configuration["Jwt:Issuer"];
        _audience = configuration["Jwt:Audience"];

        // Carregar a chave privada
        var privateKeyPath = configuration["Jwt:PrivateKeyPath"];
        if (string.IsNullOrEmpty(privateKeyPath) || !System.IO.File.Exists(privateKeyPath))
        {
            throw new FileNotFoundException($"Private key file not found at {privateKeyPath}");
        }

        var rsaPrivate = RSA.Create();
        rsaPrivate.ImportFromPem(System.IO.File.ReadAllText(privateKeyPath).ToCharArray());
        _privateKey = new RsaSecurityKey(rsaPrivate);
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginModel login)
    {
        // Simulação de validação de credenciais
        if (login.Username != "testuser" || login.Password != "testpassword")
        {
            return Unauthorized("Invalid credentials");
        }

        // Gerar Claims para o Token
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, login.Username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Role, "User")
        };

        // Configurar o token JWT
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(30),
            SigningCredentials = new SigningCredentials(_privateKey, SecurityAlgorithms.RsaSha256),
            Issuer = "YourAuthService",
            Audience = "YourMicroservices"
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);

        return Ok(new
        {
            token = tokenHandler.WriteToken(token),
            expires = tokenDescriptor.Expires
        });
    }
}
