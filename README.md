# MCP Service Account Authentication System

This ASP.NET Core Razor Pages application provides a **secure authentication foundation for Model Context Protocol (MCP) servers**, eliminating the need to store personal API keys or private credentials on developer machines or in repositories.

## 🔐 Security-First Approach: Service Accounts vs Personal Credentials

### The Problem with Personal Credentials
- ❌ **Private keys stored locally** on developer machines
- ❌ **Personal API tokens in repositories** (accidental commits)
- ❌ **Individual credential management** across teams
- ❌ **No centralized access control** or audit trails
- ❌ **Credential rotation requires individual action** from each developer

### The Service Account Solution
- ✅ **Centralized credential management** through enterprise identity providers
- ✅ **No private keys on local machines** - tokens acquired dynamically
- ✅ **Team-based access control** with scope-based permissions
- ✅ **Automated credential rotation** without developer intervention
- ✅ **Complete audit trails** for all authentication events
- ✅ **Zero-trust architecture** for AI-assisted development

## Overview

This application simulates an OAuth 2.0 authorization server that:
- **Authenticates MCP servers using service account credentials** instead of personal tokens
- **Issues dynamic, time-limited JWT tokens** for secure API access
- **Provides comprehensive logging** for enterprise security monitoring
- **Eliminates credential storage** on developer workstations

## Features

### 🔐 Service Account Authentication for MCP Servers
- **Eliminates personal credential storage** on developer machines
- **Centralizes access control** through enterprise identity providers
- **Provides dynamic token acquisition** for MCP server operations
- **Enables team-based permission management** with granular scopes

### 🎯 Enterprise-Grade Security
- **Zero local credential storage** - all tokens acquired at runtime
- **Time-limited JWT tokens** with automatic expiration
- **Scope-based access control** for fine-grained permissions
- **Comprehensive audit logging** for compliance and monitoring

### 📝 MCP Server Integration
- **VS Code MCP server authentication** without personal tokens
- **GitHub Copilot integration** with enterprise security
- **Real-time context access** through authenticated API calls
- **Multi-environment support** (dev, staging, production)

## Pre-configured Service Accounts

The application includes service accounts specifically designed for **MCP server authentication**:

### MCP Read-Only Service Account
- **Client ID**: `0oa8f5j3ecb5w3dF35d7`
- **Client Secret**: `a_very_secret_mock_value_for_alpha`
- **Scopes**: `mcp:projects:read`, `mcp:documentation:read`
- **Use Case**: VS Code MCP servers requiring read-only access to project data

### MCP Read/Write Service Account
- **Client ID**: `0oa9g2k1idg9x7eE45d8`
- **Client Secret**: `another_super_secret_for_beta_writer`
- **Scopes**: `mcp:projects:read`, `mcp:projects:write`, `mcp:teams:read`
- **Use Case**: GitHub Copilot extensions requiring project management capabilities

> 🔒 **Security Note**: These service accounts are managed centrally and **never stored on developer machines**. MCP servers acquire tokens dynamically at runtime.

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

## Security Architecture

### Traditional Approach (❌ Insecure)
```
Developer Machine:
├── .env files with personal API keys
├── ~/.aws/credentials with personal tokens  
├── Personal GitHub tokens in repositories
└── Individual OAuth apps with private keys
```

### Service Account Approach (✅ Secure)
```
MCP Server Runtime:
├── Dynamic token acquisition from identity provider
├── Service account credentials (never stored locally)
├── Time-limited, scope-specific JWT tokens
└── Centralized audit and access control
```

## Security Considerations

### ✅ **Production-Ready Security Patterns**
- **Service accounts eliminate personal credential exposure**
- **Dynamic token acquisition prevents credential theft**
- **Centralized identity management** through enterprise providers
- **Scope-based access control** limits blast radius of compromised tokens
- **Comprehensive audit logging** for security monitoring

### 🔒 **Zero Local Credential Storage**
- MCP servers **never store credentials locally**
- All authentication happens **at runtime through secure channels**
- Service account credentials are **managed centrally** by IT security teams
- **Automatic credential rotation** without developer intervention

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

This application serves as the **secure authentication foundation** for Model Context Protocol (MCP) servers in Visual Studio Code and GitHub Copilot environments. See `MCP_CONFIG.md` for comprehensive configuration guides including:

### 🔐 **Secure MCP Server Authentication**
- **Service account-based authentication** eliminating personal credential storage
- **Dynamic token acquisition** for runtime security
- **Enterprise identity provider integration** for centralized access control

### 🤖 **AI-Assisted Development Security**
- **Zero-trust architecture** for GitHub Copilot integration
- **Scope-based permissions** for AI context access
- **Audit trails** for all AI-to-API communication

### 🏢 **Enterprise-Ready Configuration**
- **Multi-environment support** (dev, staging, production)
- **Team-based access control** through service accounts
- **Compliance-ready logging** and monitoring

### Key Benefits
- 🔗 **VS Code MCP Server Setup**: Complete configuration for secure AI-assisted development
- 🤖 **GitHub Copilot Integration**: Enhanced context without credential exposure
- 🔐 **OAuth 2.0 Authentication Flow**: Service account-based security architecture
- 📊 **Real-time Project Context**: Secure access to Werner APIs, documentation, and team data
- 🛠️ **Custom Tools and Resources**: Authenticated project management without personal tokens

## License

This project is provided as-is for educational and development purposes.
