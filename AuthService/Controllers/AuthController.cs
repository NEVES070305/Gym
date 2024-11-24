using Microsoft.AspNetCore.Mvc;
using AuthService.Models;
using AuthService.Business.Interfaces;
using AuthService.Models.Refresh;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
  
    private readonly IAuthBusiness _authBusiness;

    public AuthController(IAuthBusiness authBusiness)
    {
        _authBusiness = authBusiness;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel login)
    {
        try
        {
            var (accessToken, refreshToken) = await _authBusiness.LoginAsync(login.Username, login.Password);
            return Ok(new { accessToken, refreshToken });
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(ex.Message);
        }
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
    {
        try
        {
            var (newAccessToken, newRefreshToken) = await _authBusiness.RefreshAsync(request.UserId, request.RefreshToken);
            return Ok(new { accessToken = newAccessToken, refreshToken = newRefreshToken });
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(ex.Message);
        }
    }
}
