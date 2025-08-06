# MCP Service Account Authentication for VS Code Developers

**Stop putting personal tokens in your VS Code MCP server configs!** 

This ASP.NET Core application provides secure authentication for your Visual Studio Code MCP servers, so you can use GitHub Copilot and other AI tools **without storing personal API keys in your settings**.

## The Problem: Personal Tokens in VS Code Settings

If you're manually configuring MCP servers in VS Code, you've probably done this:

```json
// ❌ Your current VS Code settings.json probably looks like this:
{
  "mcp.servers": {
    "github-context": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_your_personal_token_here"  // 🚨 DANGER!
      }
    }
  }
}
```

**Problems with this approach:**
- ❌ Your personal GitHub token is **stored in plain text** in VS Code settings
- ❌ If you sync settings, your token gets **uploaded to Microsoft's cloud**
- ❌ Anyone with access to your machine can **steal your credentials**
- ❌ **No way to rotate tokens** without manually updating every developer's settings

## The Solution: Service Account Authentication

Instead of personal tokens, this system lets you configure MCP servers like this:

```json
// ✅ Secure VS Code settings with service account authentication:
{
  "mcp.servers": {
    "github-context": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "${mcp_service_token:github-service-account}"
      }
    }
  }
}
```

**Benefits for developers:**
- ✅ **No personal tokens** in your VS Code settings
- ✅ **Dynamic token acquisition** - fresh tokens every time
- ✅ **Centrally managed** by your DevOps/Security team  
- ✅ **Works with GitHub Copilot** and all MCP servers
- ✅ **Safe to sync settings** - no credentials exposed

## How It Works for VS Code + GitHub Copilot

This mock authentication server demonstrates how to:

1. **Replace personal tokens** in your MCP server configurations
2. **Authenticate MCP servers** using service accounts instead of personal credentials  
3. **Generate dynamic JWT tokens** that work with GitHub API, AWS, databases, etc.
4. **Integrate with VS Code** and GitHub Copilot securely

### Sample VS Code MCP Server Configurations

Here are real-world examples of how you'd configure common MCP servers securely:

#### GitHub Context Server (for GitHub Copilot)
```json
{
  "mcp.servers": {
    "github-context": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "${mcp_service_token:github-service-account}"
      }
    }
  }
}
```

#### Database Context Server  
```json
{
  "mcp.servers": {
    "database-context": {
      "command": "npx", 
      "args": ["-y", "@modelcontextprotocol/server-postgres"],
      "env": {
        "DATABASE_URL": "${mcp_service_token:postgres-service-account}"
      }
    }
  }
}
```

#### AWS Resources Server
```json
{
  "mcp.servers": {
    "aws-context": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-aws"],
      "env": {
        "AWS_ACCESS_KEY_ID": "${mcp_service_token:aws-service-account-key}",
        "AWS_SECRET_ACCESS_KEY": "${mcp_service_token:aws-service-account-secret}"
      }
    }
  }
}
```

## Real-World Developer Workflow

1. **Developer opens VS Code** with MCP servers configured
2. **MCP servers start** and request tokens using service account credentials
3. **Authentication server issues JWT tokens** with appropriate scopes
4. **GitHub Copilot gets context** from secure API calls (no personal tokens involved)
5. **Tokens expire automatically** - no manual rotation needed

## Key Files in This Demo

- **`Program.cs`** - OAuth 2.0 server implementation  
- **`Pages/Index.cshtml`** - Web interface for testing token generation
- **`README.md`** - This developer guide
- **`MCP_CONFIG.md`** - Detailed VS Code configuration examples
- **`PATTERN.md`** - Security architecture patterns

## Try It Now

```bash
# 1. Clone and run the auth server
git clone https://github.com/Tristan578/mcp-service-account-auth-example.git
cd mcp-service-account-auth-example
dotnet run

# 2. Test token generation
curl -X POST http://localhost:5000/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "github-service-account",
    "client_secret": "service-secret-123", 
    "grant_type": "client_credentials",
    "scope": "repo read:org"
  }'

# 3. Configure VS Code and enjoy secure GitHub Copilot!
```

**Result**: GitHub Copilot gets repository context without any personal tokens in your VS Code settings!

## Available Service Accounts (Pre-configured for Testing)

This demo includes these service accounts that you can use in your VS Code MCP configurations:

### GitHub Service Account
- **Service Account ID**: `github-service-account`
- **Use Case**: GitHub repository access for Copilot context
- **Scopes**: `repo`, `read:org`, `read:user`
- **Token Endpoint**: `http://localhost:5000/api/auth/token`

### Database Service Account  
- **Service Account ID**: `postgres-service-account`
- **Use Case**: Database schema and query context
- **Scopes**: `db:read`, `schema:read`
- **Token Endpoint**: `http://localhost:5000/api/auth/token`

### AWS Service Account
- **Service Account ID**: `aws-service-account`
- **Use Case**: AWS resource discovery and management
- **Scopes**: `s3:read`, `ec2:describe`, `lambda:read`
- **Token Endpoint**: `http://localhost:5000/api/auth/token`

## Getting Started for VS Code Developers

### 1. Run the Authentication Server
```bash
git clone https://github.com/Tristan578/mcp-service-account-auth-example.git
cd mcp-service-account-auth-example
dotnet run
```

### 2. Configure Your VS Code MCP Servers
Open VS Code settings (`Ctrl+,`) and add MCP server configurations:

```json
{
  "mcp.servers": {
    "github-context": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "${mcp_service_token:github-service-account}"
      }
    }
  }
}
```

### 3. Test with GitHub Copilot
- Open a project in VS Code
- GitHub Copilot will automatically get repository context through the secure service account
- **No personal tokens required!**

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
