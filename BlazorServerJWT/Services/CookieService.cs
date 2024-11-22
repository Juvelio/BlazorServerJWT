using Microsoft.JSInterop;

namespace BlazorServerJWT.Services
{
    public class CookieService
    {
        private readonly IJSRuntime jSRuntime;

        public CookieService(IJSRuntime jSRuntime)
        {
            this.jSRuntime = jSRuntime;
        }

        public async Task SetCookieAsync(string name, string value, int days)
        {
            await jSRuntime.InvokeVoidAsync("setCookie", name, value, days);
        }

        public async Task DeleteCookieAsync(string name)
        {
            await jSRuntime.InvokeVoidAsync("deleteCookie", name);
        }

        public async Task<string> GetCookieAsync(string name)
        {
            return await jSRuntime.InvokeAsync<string>("getCookie", name);
        }
    }
}
