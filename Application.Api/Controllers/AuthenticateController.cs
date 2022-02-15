using Application.Data.Model;
using Microsoft.AspNetCore.Mvc;
using Application.Core.Services.Itf;

namespace Application.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly IAuthenticationService _authenticationService;

        public AuthenticateController(IAuthenticationService authenticationService)
        {
            _authenticationService = authenticationService;
        }
        //[HttpPost]
        //[Route("login")]
        //public async Task<IActionResult> Login([FromBody] LoginModel model)
        //{
        //    return Ok(await _authenticationService.Login(model));
        //}

        //[HttpPost]
        //[Route("register")]
        //public async Task<IActionResult> Register([FromBody] RegisterModel model)
        //{
        //    return null;
        //}

        //[HttpPost]
        //[Route("register-admin")]
        //public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        //{
        //    return null;
        //}

        //[HttpPost]
        //[Route("register-superadmin")]
        //public async Task<IActionResult> RegisterSuperAdmin([FromBody] RegisterModel model)
        //{
        //    return null;
        //}

    }
}
