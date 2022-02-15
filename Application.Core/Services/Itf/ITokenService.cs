using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Application.Data.Model;

namespace Application.Core.Services.Itf
{
    public interface ITokenService
    {
        Task<Response> RefreshToken(TokenModel? tokenModel);
        Task<Response> Revoke(string username);
        Task<Response> RevokeAll();
        JwtSecurityToken CreateToken(List<Claim> authClaims);
        ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token);
    }
}
