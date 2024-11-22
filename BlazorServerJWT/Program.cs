using BlazorServerJWT.Auth;
using BlazorServerJWT.Components;
using BlazorServerJWT.Services;
using Microsoft.AspNetCore.Components.Authorization;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();


#region Authentication
builder.Services.AddAuthorizationCore();
builder.Services.AddScoped<CustomAuthenticationStateComponent>();
builder.Services.AddScoped<CookieService>();

//builder.Services.AddAuthentication()
//    .AddScheme<CustomOptions, CustomAuthenticationHandler>("CustomAuth", options =>
//    {

//    });

builder.Services.AddAuthentication("CustomAuth")
    .AddCookie("CustomAuth", options =>
    {
        options.LoginPath = "/login";

        //options.ExpireTimeSpan = TimeSpan.FromMinutes(1); // Tiempo de expiración de la sesión (ejemplo: 30 minutos)
        //options.SlidingExpiration = true; // Renueva la expiración con cada solicitud

        options.ExpireTimeSpan = TimeSpan.FromMinutes(1); // Expira en 30 minutos
        options.SlidingExpiration = true; // Renueva la expiraci�n con cada solicitud
        options.Cookie.HttpOnly = true; // Proteger la cookie contra acceso del lado del cliente
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Asegurarse de que la cookie solo se env�e a travs de HTTPS
    });


builder.Services.AddScoped<CustomAuthenticationStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(provider => provider.GetRequiredService<CustomAuthenticationStateProvider>());
builder.Services.AddCascadingAuthenticationState();
#endregion


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
