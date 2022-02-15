using Application.Data.Model;
using Microsoft.AspNetCore.Mvc;

namespace Application.Core.Services.Itf
{
    public interface IAuthenticationService
    {
        Task<Response> Login([FromBody] LoginModel model);
        Task<Response> Register([FromBody] RegisterModel model);
        Task<Response> RegisterAdmin([FromBody] RegisterModel model);
        Task<Response> RegisterSuperAdmin([FromBody] RegisterModel model);
    }
}
