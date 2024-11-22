using Microsoft.AspNetCore.Components.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace BlazorServerJWT.Auth
{
    public class CustomAuthenticationStateProvider : AuthenticationStateProvider
    {
        private readonly CustomAuthenticationStateComponent authComponent;
        private ClaimsPrincipal _anonymous = new ClaimsPrincipal(new ClaimsIdentity());

        public CustomAuthenticationStateProvider(CustomAuthenticationStateComponent authComponent)
        {
            this.authComponent = authComponent;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            try
            {
                var userClaim = await authComponent.VerifyUser();
                if (userClaim != null)
                {
                    var identity = new ClaimsIdentity(userClaim, "JWT");
                    var user = new ClaimsPrincipal(identity);
                    return await Task.FromResult(new AuthenticationState(user));
                }
                else
                {
                    await authComponent.DeleteTokenFromCookie();
                    return new AuthenticationState(_anonymous);
                }
            }
            catch (Exception)
            {
                return new AuthenticationState(_anonymous);
            }
        }

        public async Task AuthenticateUser(User _user)
        {
            //Need component to create JWT
            //JWT into cookies
            var token = await authComponent.Auth(_user);
            if (!string.IsNullOrEmpty(token))
            {
                var readJWT = new JwtSecurityTokenHandler().ReadJwtToken(token);
                var identity = new ClaimsIdentity(readJWT.Claims, "JWT");
                var user = new ClaimsPrincipal(identity);
                var state = new AuthenticationState(user);
                NotifyAuthenticationStateChanged(Task.FromResult(state));
            }
            else
            {
                //do nothing
            }
        }

        public async Task Logout()
        {
            await authComponent.DeleteTokenFromCookie();
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(_anonymous)));
        }
    }
}
