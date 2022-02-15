using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Application.Core.Services.Itf;
using Application.Data.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;

namespace Application.Core.Services.Impl
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ITokenService _tokenService;
        private readonly IConfiguration _configuration;
        public AuthenticationService(UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            ITokenService tokenService,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _tokenService = tokenService;
            _configuration = configuration;
        }
        public async Task<Response> Login(LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var token = _tokenService.CreateToken(authClaims);
                var refreshToken = TokenService.GenerateRefreshToken();

                _ = int.TryParse(_configuration["JWT:RefreshTokenValidityInDays"], out int refreshTokenValidityInDays);

                user.RefreshToken = refreshToken;
                user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays).ToUniversalTime();

                await _userManager.UpdateAsync(user);

                var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

                return new Response
                        {
                            Status = "200:success",
                            Message = $"Token : {jwtToken}, RefreshToken : {refreshToken}, Expiration : {token.ValidTo}"
                        };
            }
            return new Response
            {
                Status = "401:unauthorized",
                Message = "Wrong credentials."
            };
        }

        public async Task<Response> Register(RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return new Response {Status = "500:error", Message = "User already exists!"};

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return new Response { Status = "500:error", Message = "User creation failed! Please check user details and try again." };

            await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));
            await _userManager.AddToRoleAsync(user, UserRoles.User);


            return new Response { Status = "200:success", Message = "User created successfully!" };
        }

        public async Task<Response> RegisterAdmin(RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return new Response { Status = "500:error", Message = "Admin already exists!" };

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return new Response { Status = "500:error", Message = "Admin creation failed! Please check user details and try again." };

            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
            if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));
           
            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.Admin);
            }
            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.User);
            }
            return new Response { Status = "200:success", Message = "Admin created successfully!" };
        }

        public async Task<Response> RegisterSuperAdmin(RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return new Response { Status = "500:error", Message = "SuperAdmin already exists!" };

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return new Response { Status = "500:error", Message = "SuperAdmin creation failed! Please check user details and try again." };

            if (!await _roleManager.RoleExistsAsync("SuperAdmin"))
                await _roleManager.CreateAsync(new IdentityRole("SuperAdmin"));
            if (!await _roleManager.RoleExistsAsync("Admin"))
                await _roleManager.CreateAsync(new IdentityRole("Admin"));
            if (!await _roleManager.RoleExistsAsync("User"))
                await _roleManager.CreateAsync(new IdentityRole("User"));
            if (await _roleManager.RoleExistsAsync("SuperAdmin"))
            {
                await _userManager.AddToRoleAsync(user, "SuperAdmin");
            }
            if (await _roleManager.RoleExistsAsync("SuperAdmin"))
            {
                await _userManager.AddToRoleAsync(user, "Admin");
            }
            if (await _roleManager.RoleExistsAsync("SuperAdmin"))
            {
                await _userManager.AddToRoleAsync(user, "User");
            }
            return new Response { Status = "200:success", Message = "SuperAdmin created successfully!" };
        }
    }
}
