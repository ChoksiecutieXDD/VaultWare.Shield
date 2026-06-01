using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.IO;

var options = new WebApplicationOptions
{
    Args = args,
    // FIX: Force the app to look for Views/wwwroot in the .exe folder
    ContentRootPath = AppContext.BaseDirectory
};

var builder = WebApplication.CreateBuilder(options);

// Add services to the container.
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
}

app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// FIX: Initialize the Engine immediately so database files are created before the UI loads
try
{
    VaultWare.Shield.Models.SecurityEngine.Initialize();
}
catch (Exception ex)
{
    // If initialization fails, log it to a file on the desktop so we know why
    string logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "vaultware_crash_log.txt");
    File.WriteAllText(logPath, "Startup Crash: " + ex.ToString());
}

app.Run();