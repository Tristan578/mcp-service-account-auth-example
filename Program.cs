using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddRazorPages();

// Configure logging to include console and file logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

// Add file logging for authentication events
builder.Logging.AddConfiguration(builder.Configuration.GetSection("Logging"));

// Configure HTTP request logging
builder.Services.AddHttpLogging(logging =>
{
    logging.LoggingFields = Microsoft.AspNetCore.HttpLogging.HttpLoggingFields.RequestHeaders |
                           Microsoft.AspNetCore.HttpLogging.HttpLoggingFields.RequestBody |
                           Microsoft.AspNetCore.HttpLogging.HttpLoggingFields.ResponseHeaders |
                           Microsoft.AspNetCore.HttpLogging.HttpLoggingFields.ResponseBody;
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

// Configure forwarded headers for proper IP address detection behind reverse proxies
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

// Enable HTTP request logging
app.UseHttpLogging();

app.MapRazorPages();

// Ensure auth.log file exists and create startup log entry
var logFilePath = Path.Combine(Directory.GetCurrentDirectory(), "auth.log");
var startupMessage = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}] STARTUP | Mock Okta Token Endpoint started | Environment: {app.Environment.EnvironmentName}";

try
{
    if (!File.Exists(logFilePath))
    {
        await File.WriteAllTextAsync(logFilePath, $"# Mock Okta Token Endpoint Authentication Log{Environment.NewLine}");
        await File.AppendAllTextAsync(logFilePath, $"# Log format: [timestamp] RESULT | Client ID: clientId | IP: ipAddress | Additional Info{Environment.NewLine}");
        await File.AppendAllTextAsync(logFilePath, $"#{Environment.NewLine}");
    }
    
    await File.AppendAllTextAsync(logFilePath, startupMessage + Environment.NewLine);
}
catch (Exception ex)
{
    var logger = app.Services.GetRequiredService<ILogger<Program>>();
    logger.LogError(ex, "Failed to initialize auth.log file");
}

// Log startup information
var startupLogger = app.Services.GetRequiredService<ILogger<Program>>();
startupLogger.LogInformation("Mock Okta Token Endpoint started successfully");
startupLogger.LogInformation("Authentication logs will be written to: {LogFilePath}", logFilePath);
startupLogger.LogInformation("Available service accounts: github-service-account, sqlserver-service-account, azure-service-account, mulesoft-service-account, sonarqube-service-account, playwright-service-account");

app.Run();
