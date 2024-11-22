using BlazorServerJWT.Services;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace BlazorServerJWT.Auth
{
    public class CustomAuthenticationStateComponent
    {
        private readonly string key = "Esta es mi clave secreta personalizada 123";
        private readonly CookieService cookieService;
        private readonly string cookiesKey = "auth_token";

        public CustomAuthenticationStateComponent(CookieService cookieService)
        {
            this.cookieService = cookieService;
        }

        public async Task<string> Auth(User user)
        {
            var token = GenerateJWT(user);

            //set cookies
            await cookieService.SetCookieAsync(cookiesKey, token, 1);
            return token;
        }


        private string GenerateJWT(User user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var token = new JwtSecurityToken(
                issuer: "your-issuer",
                audience: "your-audience",
                claims: claims,
                expires: DateTime.Now.AddMinutes(1),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        internal async Task DeleteTokenFromCookie()
        {
            await cookieService.DeleteCookieAsync(cookiesKey);
        }

        public async Task<IEnumerable<Claim>?> VerifyUser()
        {
            var token = await cookieService.GetCookieAsync(cookiesKey);
            if (token == null) return null;

            return VerifyUser(token);
        }

        public IEnumerable<Claim>? VerifyUser(string token)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var tokenHandler = new JwtSecurityTokenHandler();

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = "your-issuer",
                ValidAudience = "your-audience",
                IssuerSigningKey = securityKey
            };

            try
            {
                tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
                var jsonToken = tokenHandler.ReadToken(token) as JwtSecurityToken;
                if (jsonToken != null)
                {
                    return jsonToken.Claims.ToList();
                }
            }
            catch (Exception)
            {
            }

            return null;
        }
    }
}
