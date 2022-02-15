using Application.Data.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Application.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        //[HttpPost]
        //[Route("refresh-token")]
        //public async Task<IActionResult> RefreshToken(TokenModel tokenModel)
        //{
        //    return null;
        //}

        //[Authorize]
        //[HttpPost]
        //[Route("revoke/{username}")]
        //public async Task<IActionResult> Revoke(string username)
        //{
        //    return null;
        //}

        //[Authorize]
        //[HttpPost]
        //[Route("revoke-all")]
        //public async Task<IActionResult> RevokeAll()
        //{
        //    return null;
        //}
    }
}
