using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text;
using System.Text.Json;

namespace mcp_service_account_auth_example.Pages;

public class IndexModel : PageModel
{
    private readonly ILogger<IndexModel> _logger;

    // Record to represent a service account for MCP server authentication
    // These service accounts eliminate the need for personal credentials on developer machines
    private record OktaClient(string ClientSecret, string[] Scopes);

    // Dictionary to store valid MCP service account clients
    // In production, these would be managed centrally by enterprise identity providers
    private readonly Dictionary<string, OktaClient> _validClients = new()
    {
        // MCP Read-Only Service Account - for VS Code context servers
        ["0oa8f5j3ecb5w3dF35d7"] = new OktaClient(
            ClientSecret: "a_very_secret_mock_value_for_alpha",
            Scopes: new[] { "mcp:projects:read", "mcp:documentation:read" }
        ),
        // MCP Read/Write Service Account - for GitHub Copilot with enhanced capabilities  
        ["0oa9g2k1idg9x7eE45d8"] = new OktaClient(
            ClientSecret: "another_super_secret_for_beta_writer",
            Scopes: new[] { "mcp:projects:read", "mcp:projects:write", "mcp:teams:read" }
        )
    };

    public IndexModel(ILogger<IndexModel> logger)
    {
        _logger = logger;
    }

    [BindProperty]
    public string ClientId { get; set; } = string.Empty;

    [BindProperty]
    public string ClientSecret { get; set; } = string.Empty;

    public string ResultMessage { get; set; } = string.Empty;
    public bool IsSuccess { get; set; }
    public string GeneratedToken { get; set; } = string.Empty;
    public string[] TokenScopes { get; set; } = Array.Empty<string>();
    public DateTime? TokenExpiration { get; set; }

    public void OnGet()
    {
        // Initialize empty form
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var clientIp = GetClientIpAddress();
        var timestamp = DateTime.UtcNow;

        try
        {
            // Validate input
            if (string.IsNullOrWhiteSpace(ClientId) || string.IsNullOrWhiteSpace(ClientSecret))
            {
                SetFailureResult("Client ID and Client Secret are required.");
                await LogAuthenticationAttempt(timestamp, "FAILURE", ClientId, clientIp, "Missing credentials");
                return Page();
            }

            // Check if client exists
            if (!_validClients.TryGetValue(ClientId, out var oktaClient))
            {
                SetFailureResult("Invalid Client ID or Client Secret.");
                await LogAuthenticationAttempt(timestamp, "FAILURE", ClientId, clientIp, "Invalid Client ID");
                return Page();
            }

            // Validate client secret
            if (oktaClient.ClientSecret != ClientSecret)
            {
                SetFailureResult("Invalid Client ID or Client Secret.");
                await LogAuthenticationAttempt(timestamp, "FAILURE", ClientId, clientIp, "Invalid Client Secret");
                return Page();
            }

            // Generate mock JWT token
            var token = GenerateMockJwt(ClientId, oktaClient.Scopes, timestamp);
            var expirationTime = timestamp.AddHours(1);

            SetSuccessResult(
                "Authentication successful! JWT token generated.",
                token,
                oktaClient.Scopes,
                expirationTime
            );

            await LogAuthenticationAttempt(timestamp, "SUCCESS", ClientId, clientIp, $"Scopes: {string.Join(", ", oktaClient.Scopes)}");
            
            return Page();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during authentication process for Client ID: {ClientId}", ClientId);
            SetFailureResult("An internal error occurred during authentication.");
            await LogAuthenticationAttempt(timestamp, "FAILURE", ClientId, clientIp, $"Internal error: {ex.Message}");
            return Page();
        }
    }

    private string GenerateMockJwt(string clientId, string[] scopes, DateTime issuedAt)
    {
        var expiration = issuedAt.AddHours(1);

        // Create JWT Header
        var header = new
        {
            alg = "HS256",
            typ = "JWT"
        };

        // Create JWT Payload
        var payload = new
        {
            iss = "https://dev-12345.okta.com/oauth2/default",
            sub = clientId,
            aud = "api://mcp-server",
            scp = scopes,
            iat = ((DateTimeOffset)issuedAt).ToUnixTimeSeconds(),
            exp = ((DateTimeOffset)expiration).ToUnixTimeSeconds()
        };

        // Serialize to JSON and Base64Url encode
        var headerJson = JsonSerializer.Serialize(header);
        var payloadJson = JsonSerializer.Serialize(payload);

        var headerEncoded = Base64UrlEncode(headerJson);
        var payloadEncoded = Base64UrlEncode(payloadJson);

        // Mock signature (in real implementation, this would be cryptographically signed)
        var signature = "mock-signature-sLw6mSHh9s";

        // Combine all parts
        return $"{headerEncoded}.{payloadEncoded}.{signature}";
    }

    private static string Base64UrlEncode(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var base64 = Convert.ToBase64String(bytes);
        
        // Convert to Base64Url encoding
        return base64.Replace('+', '-')
                    .Replace('/', '_')
                    .TrimEnd('=');
    }

    private string GetClientIpAddress()
    {
        // Try to get the real IP address from headers (for reverse proxy scenarios)
        var xForwardedFor = Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(xForwardedFor))
        {
            return xForwardedFor.Split(',')[0].Trim();
        }

        var xRealIp = Request.Headers["X-Real-IP"].FirstOrDefault();
        if (!string.IsNullOrEmpty(xRealIp))
        {
            return xRealIp;
        }

        // Fallback to connection remote IP
        return Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
    }

    private async Task LogAuthenticationAttempt(DateTime timestamp, string result, string clientId, string clientIp, string additionalInfo)
    {
        var logMessage = $"[{timestamp:yyyy-MM-dd HH:mm:ss UTC}] {result} | Client ID: {clientId} | IP: {clientIp} | {additionalInfo}";
        
        // Log to console/default logger
        if (result == "SUCCESS")
        {
            _logger.LogInformation("Authentication {Result}: Client ID {ClientId} from IP {ClientIp} - {AdditionalInfo}", 
                result, clientId, clientIp, additionalInfo);
        }
        else
        {
            _logger.LogWarning("Authentication {Result}: Client ID {ClientId} from IP {ClientIp} - {AdditionalInfo}", 
                result, clientId, clientIp, additionalInfo);
        }

        // Also write to auth.log file
        try
        {
            var logFilePath = Path.Combine(Directory.GetCurrentDirectory(), "auth.log");
            await System.IO.File.AppendAllTextAsync(logFilePath, logMessage + Environment.NewLine);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to write to auth.log file");
        }
    }

    private void SetSuccessResult(string message, string token, string[] scopes, DateTime expiration)
    {
        IsSuccess = true;
        ResultMessage = message;
        GeneratedToken = token;
        TokenScopes = scopes;
        TokenExpiration = expiration;
    }

    private void SetFailureResult(string message)
    {
        IsSuccess = false;
        ResultMessage = message;
        GeneratedToken = string.Empty;
        TokenScopes = Array.Empty<string>();
        TokenExpiration = null;
    }
}
