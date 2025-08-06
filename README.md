# Mock Okta Token Endpoint

This ASP.NET Core Razor Pages application simulates an OAuth 2.0 token endpoint, specifically mimicking how service accounts provisioned through an identity provider like **Okta** would authenticate using the **OAuth 2.0 Client Credentials flow**.

## Overview

The application acts as a mock OAuth 2.0 authorization server that:
- Accepts Client ID and Client Secret credentials
- Validates them against a pre-configured set of service accounts
- Issues structurally correct JSON Web Tokens (JWTs) upon successful authentication
- Logs all authentication attempts for security monitoring

## Features

### 🔐 OAuth 2.0 Client Credentials Flow Simulation
- Mimics real-world service account authentication
- Validates client credentials against a secure registry
- Issues time-limited JWT tokens with appropriate scopes

### 🎯 Realistic JWT Generation
- **Header**: Includes algorithm and token type
- **Payload**: Contains standard OAuth 2.0 claims (iss, sub, aud, scp, iat, exp)
- **Signature**: Mock signature for demonstration purposes
- **Encoding**: Proper Base64Url encoding for JWT compliance

### 📝 Comprehensive Logging
- Console logging for development visibility
- File logging to `auth.log` for persistent audit trails
- Detailed logging includes timestamps, IP addresses, and authentication results
- Separate log entries for successful and failed authentication attempts

### 🖥️ User-Friendly Interface
- Clean, responsive web interface
- Real-time feedback for authentication attempts
- JWT token display with detailed claims information
- Built-in test credentials for easy demonstration

## Pre-configured Test Clients

The application comes with two pre-configured service accounts for testing:

### Alpha Client (Read-Only Access)
- **Client ID**: `0oa8f5j3ecb5w3dF35d7`
- **Client Secret**: `a_very_secret_mock_value_for_alpha`
- **Scopes**: `mcp:projects:read`

### Beta Client (Read/Write Access)
- **Client ID**: `0oa9g2k1idg9x7eE45d8`
- **Client Secret**: `another_super_secret_for_beta_writer`
- **Scopes**: `mcp:projects:read`, `mcp:projects:write`

## Getting Started

### Prerequisites
- .NET 8.0 SDK or later
- Visual Studio 2022, Visual Studio Code, or any text editor

### Running the Application

1. **Clone or download the project**
   ```bash
   git clone <repository-url>
   cd mcp-service-account-auth-example
   ```

2. **Restore dependencies**
   ```bash
   dotnet restore
   ```

3. **Run the application**
   ```bash
   dotnet run
   ```

4. **Access the application**
   - Open your browser and navigate to `https://localhost:5001` or `http://localhost:5000`
   - Use the pre-configured client credentials to test the authentication flow

### Testing the Authentication Flow

1. **Successful Authentication**:
   - Enter one of the pre-configured Client IDs
   - Enter the corresponding Client Secret
   - Click "Get Token"
   - View the generated JWT and token information

2. **Failed Authentication**:
   - Try entering an invalid Client ID or Client Secret
   - Observe the error message and check the logs

## Generated JWT Structure

The mock JWT tokens contain the following claims:

```json
{
  "iss": "https://dev-12345.okta.com/oauth2/default",
  "sub": "{client_id}",
  "aud": "api://mcp-server",
  "scp": ["{scopes}"],
  "iat": {issued_at_timestamp},
  "exp": {expiration_timestamp}
}
```

## Logging and Monitoring

### Console Logs
All authentication attempts are logged to the console with different log levels:
- **Information**: Successful authentication attempts
- **Warning**: Failed authentication attempts
- **Error**: System errors during authentication

### File Logs (`auth.log`)
Persistent logging to `auth.log` file in the application root directory:
```
[2025-08-06 14:30:15 UTC] SUCCESS | Client ID: 0oa8f5j3ecb5w3dF35d7 | IP: 192.168.1.100 | Scopes: mcp:projects:read
[2025-08-06 14:31:22 UTC] FAILURE | Client ID: invalid_client | IP: 192.168.1.100 | Invalid Client ID
```

## Project Structure

```
mcp-service-account-auth-example/
├── Pages/
│   ├── Index.cshtml           # Main UI with authentication form
│   └── Index.cshtml.cs        # PageModel with authentication logic
├── Program.cs                 # Application startup and configuration
├── README.md                  # This documentation
├── PATTERN.md                 # OAuth 2.0 pattern documentation
└── auth.log                   # Authentication log file (created at runtime)
```

## Security Considerations

⚠️ **Important**: This is a **mock application** for development and testing purposes only.

- Client secrets are stored in plain text in code
- JWT signature is not cryptographically valid
- No rate limiting or advanced security measures implemented
- Not suitable for production use without significant security enhancements

## Extending the Application

### Adding New Service Accounts
Edit the `_validClients` dictionary in `Pages/Index.cshtml.cs`:

```csharp
private readonly Dictionary<string, OktaClient> _validClients = new()
{
    // Add new clients here
    ["your_new_client_id"] = new OktaClient(
        ClientSecret: "your_secret_here",
        Scopes: new[] { "your:scopes:here" }
    )
};
```

### Customizing JWT Claims
Modify the payload creation in the `GenerateMockJwt` method to add additional claims or change existing ones.

### Enhanced Logging
Extend the logging functionality in the `LogAuthenticationAttempt` method to include additional metadata or integrate with external logging systems.

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   - Change the port in `Properties/launchSettings.json` or use `dotnet run --urls "https://localhost:5002"`

2. **Logging Permission Issues**
   - Ensure the application has write permissions to the directory for creating `auth.log`

3. **IP Address Shows as "Unknown"**
   - This is normal when running locally; the application will show proper IP addresses when deployed

## Next Steps

After running this mock application, consider:
- Reviewing the `PATTERN.md` file for OAuth 2.0 best practices
- Exploring the `MCP_CONFIG.md` file for Model Context Protocol integration with VS Code and GitHub Copilot
- Implementing real JWT signature validation
- Adding database storage for service accounts
- Implementing proper secret management
- Adding rate limiting and security headers

## MCP Integration

This application serves as the foundation for **Model Context Protocol (MCP) server authentication** in Visual Studio Code and GitHub Copilot environments. See `MCP_CONFIG.md` for comprehensive configuration guides including:

- 🔗 **VS Code MCP Server Setup**: Complete configuration for AI-assisted development
- 🤖 **GitHub Copilot Integration**: Enhanced context and intelligent code generation
- 🔐 **OAuth 2.0 Authentication Flow**: Secure service-to-service communication
- 📊 **Real-time Project Context**: Access to Werner APIs, documentation, and team data
- 🛠️ **Custom Tools and Resources**: Automated project management and requirement tracking

## License

This project is provided as-is for educational and development purposes.
