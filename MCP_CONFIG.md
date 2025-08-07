# VS Code MCP Server Configuration: Stop Using Personal Tokens!

**This guide shows you how to configure MCP servers in VS Code WITHOUT putting personal API tokens in your settings.**

If you're manually configuring MCP servers for GitHub Copilot and other AI tools, this is for you.

## The Problem: You're Probably Doing This

Most developers configure MCP servers like this in their VS Code `settings.json`:

```json
// ❌ INSECURE: Your settings.json probably looks like this
{
  "mcp.servers": {
    "github-context": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_xxxxxxxxxxxxxxxxxxxx"  // 🚨 Your personal token!
      }
    },
    "database-context": {
      "command": "npx", 
      "args": ["-y", "@modelcontextprotocol/server-postgres"],
      "env": {
        "DATABASE_URL": "postgres://user:password@host/db"  // 🚨 Personal credentials!
      }
    },
    "aws-context": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-aws"], 
      "env": {
        "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",      // 🚨 Personal AWS key!
        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG"  // 🚨 Personal secret!
      }
    }
  }
}
```

**Why this is dangerous:**
- 🚨 **Personal tokens stored in plain text** in VS Code settings
- 🚨 **Settings sync uploads your tokens** to Microsoft's cloud  
- 🚨 **Anyone who accesses your machine** can steal your credentials
- 🚨 **No way to rotate tokens** without updating every developer manually
- 🚨 **Tokens don't expire** - permanent security risk
## The Solution: Service Account Authentication

Instead of personal tokens, configure your MCP servers like this:

```json
// ✅ SECURE: Service account authentication in VS Code settings
{
  "mcp.servers": {
    "github-context": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "${mcp_service_token:github-service-account}"
      }
    },
    "database-context": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres"], 
      "env": {
        "DATABASE_URL": "${mcp_service_token:postgres-service-account}"
      }
    },
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

**Why this is secure:**
- ✅ **No personal tokens** in your VS Code settings
- ✅ **Dynamic token acquisition** - fresh tokens every time MCP servers start  
- ✅ **Tokens expire automatically** - no permanent credentials
- ✅ **Safe to sync settings** - no secrets exposed
- ✅ **Centrally managed** by DevOps team
- ✅ **Easy rotation** - no individual developer action needed

## Step-by-Step Setup for VS Code Developers

### Step 1: Start the Authentication Server

```bash
# Clone and run the auth server
git clone https://github.com/Tristan578/mcp-service-account-auth-example.git
cd mcp-service-account-auth-example
dotnet run
```

The server starts at `http://localhost:5000` and provides service account authentication for your MCP servers.

### Step 2: Configure VS Code MCP Servers

Open VS Code settings (`Ctrl+Shift+P` → "Preferences: Open Settings (JSON)") and configure your MCP servers:

#### Example 1: GitHub Context for Copilot
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

#### Example 2: Database Schema Context
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

#### Example 3: AWS Resources Context
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

#### Example 4: Complete Multi-Server Configuration
```json
{
  "mcp.servers": {
    "github-context": {
      "command": "npx", 
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "${mcp_service_token:github-service-account}"
      }
    },
    "database-context": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres"],
      "env": {
        "DATABASE_URL": "${mcp_service_token:postgres-service-account}"
      }
    },
    "aws-context": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-aws"],
      "env": {
        "AWS_ACCESS_KEY_ID": "${mcp_service_token:aws-service-account-key}",
        "AWS_SECRET_ACCESS_KEY": "${mcp_service_token:aws-service-account-secret}"
      }
    },
    "slack-context": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-slack"],
      "env": {
        "SLACK_BOT_TOKEN": "${mcp_service_token:slack-service-account}"
      }
    }
  }
}
```

### Step 3: Test Your Configuration

1. **Reload VS Code** (`Ctrl+Shift+P` → "Developer: Reload Window")
2. **Open a project** - any repository or folder
3. **Use GitHub Copilot** - it will automatically get context through the secure service account
4. **No personal tokens needed!**

## Available Service Accounts

This demo includes pre-configured service accounts you can use:

| Service Account ID | Use Case | What It Does |
|-------------------|----------|--------------|
| `github-service-account` | GitHub repositories | Gives Copilot access to your repo context |
| `postgres-service-account` | Database schemas | Provides database structure context |
| `aws-service-account-key` | AWS resources | AWS access key for cloud resources |
| `aws-service-account-secret` | AWS resources | AWS secret key for cloud resources |
| `slack-service-account` | Slack integration | Access to Slack channels and messages |

## Troubleshooting

### MCP Server Won't Start
```bash
# Check if the auth server is running
curl http://localhost:5000/health

# Expected response: {"status": "healthy"}
```

### Token Authentication Fails
```bash
# Test token acquisition manually
curl -X POST http://localhost:5000/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "github-service-account",
    "client_secret": "service-secret-123",
    "grant_type": "client_credentials",
    "scope": "repo read:org"
  }'
```

### VS Code Settings Sync Issues
- **Safe to sync**: Your settings only contain `${mcp_service_token:...}` placeholders
- **No secrets exposed**: Real tokens are acquired dynamically by MCP servers
- **Team sharing**: Everyone can use the same settings configuration

## How the Token Replacement Works

The `${mcp_service_token:service-account-id}` syntax is replaced by the MCP server at startup:

1. **MCP server starts** with placeholder in environment variable
2. **Server detects** the `${mcp_service_token:...}` pattern  
3. **Calls auth endpoint** to get a real token for that service account
4. **Replaces placeholder** with actual token
5. **Uses real token** for API calls

Your VS Code settings never contain real tokens - only placeholders!
      ],
      "env": {
        "OAUTH_TOKEN_ENDPOINT": "http://localhost:5000",
        "OAUTH_CLIENT_ID": "0oa8f5j3ecb5w3dF35d7",
        "OAUTH_SCOPES": "mcp:projects:read mcp:projects:write",
        "PROJECT_API_BASE": "https://api.company.com/v1",
        "LOG_LEVEL": "info"
      },
      "capabilities": {
        "resources": true,
        "tools": true,
        "prompts": true
      }
    },
    "company-documentation": {
      "command": "node",
      "args": [
        "/path/to/company-docs-mcp/dist/index.js"
      ],
      "env": {
        "OAUTH_TOKEN_ENDPOINT": "http://localhost:5000",
        "OAUTH_CLIENT_ID": "0oa9g2k1idg9x7eE45d8",
        "OAUTH_SCOPES": "mcp:documentation:read",
        "CONFLUENCE_BASE_URL": "https://company.atlassian.net",
        "CONFLUENCE_SPACE_KEY": "NAV"
      },
      "capabilities": {
        "resources": true,
        "prompts": true
      }
    }
  },
  "github.copilot.advanced": {
    "debug": true,
    "inlineSuggestEnable": true
  }
}
```

### 2. GitHub Copilot Extensions Configuration

**File**: `.github/copilot/copilot-extensions.yml`

```yaml
version: "1.0"

extensions:
  - name: "company-project-context"
    type: "mcp-server"
    config:
      oauth:
        token_endpoint: "http://localhost:5000"
        client_id: "0oa8f5j3ecb5w3dF35d7"
        scopes: 
          - "mcp:projects:read"
          - "mcp:projects:write"
      endpoints:
        - name: "projects"
          url: "https://api.company.com/v1/projects"
          methods: ["GET", "POST", "PUT"]
        - name: "requirements" 
          url: "https://api.company.com/v1/requirements"
          methods: ["GET"]
      
  - name: "company-documentation"
    type: "mcp-server"
    config:
      oauth:
        token_endpoint: "http://localhost:5000"
        client_id: "0oa9g2k1idg9x7eE45d8"
        scopes:
          - "mcp:documentation:read"
      endpoints:
        - name: "confluence"
          url: "https://company.atlassian.net/wiki/rest/api"
          methods: ["GET"]
```

### 3. MCP Server Implementation Example

**File**: `mcp-servers/company-project-context/src/index.ts`

```typescript
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  McpError,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import axios from 'axios';

interface OAuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
}

class CompanyProjectContextServer {
  private server: Server;
  private accessToken: string | null = null;
  private tokenExpires: Date | null = null;

  constructor() {
    this.server = new Server(
      {
        name: 'company-project-context',
        version: '1.0.0',
      },
      {
        capabilities: {
          resources: {},
          tools: {},
          prompts: {},
        },
      }
    );

    this.setupHandlers();
  }

  private async getAccessToken(): Promise<string> {
    // Check if current token is still valid (with 5-minute buffer)
    if (this.accessToken && this.tokenExpires && 
        this.tokenExpires > new Date(Date.now() + 5 * 60 * 1000)) {
      return this.accessToken;
    }

    // Request new token from our mock OAuth server
    try {
      const response = await axios.post<OAuthTokenResponse>(
        process.env.OAUTH_TOKEN_ENDPOINT!,
        new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: process.env.OAUTH_CLIENT_ID!,
          client_secret: process.env.OAUTH_CLIENT_SECRET!,
          scope: process.env.OAUTH_SCOPES!,
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }
      );

      this.accessToken = response.data.access_token;
      this.tokenExpires = new Date(Date.now() + response.data.expires_in * 1000);
      
      console.log(`[${new Date().toISOString()}] OAuth token acquired successfully`);
      return this.accessToken;
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Failed to acquire OAuth token:`, error);
      throw new McpError(ErrorCode.InternalError, 'Failed to acquire authentication token');
    }
  }

  private async makeAuthenticatedRequest(url: string, options: any = {}) {
    const token = await this.getAccessToken();
    
    return axios({
      ...options,
      url,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });
  }

  private setupHandlers() {
    // List available resources
    this.server.setRequestHandler(ListResourcesRequestSchema, async () => {
      return {
        resources: [
          {
            uri: 'company://projects',
            name: 'Active Projects',
            description: 'List of all active Company projects',
            mimeType: 'application/json',
          },
          {
            uri: 'company://requirements/current',
            name: 'Current Requirements',
            description: 'Current project requirements and specifications',
            mimeType: 'application/json',
          },
          {
            uri: 'company://team/members',
            name: 'Team Members',
            description: 'Active team members and their roles',
            mimeType: 'application/json',
          },
        ],
      };
    });

    // Read specific resources
    this.server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      const { uri } = request.params;

      try {
        switch (uri) {
          case 'company://projects': {
            const response = await this.makeAuthenticatedRequest(
              `${process.env.PROJECT_API_BASE}/projects`
            );
            return {
              contents: [
                {
                  uri,
                  mimeType: 'application/json',
                  text: JSON.stringify(response.data, null, 2),
                },
              ],
            };
          }

          case 'company://requirements/current': {
            const response = await this.makeAuthenticatedRequest(
              `${process.env.PROJECT_API_BASE}/requirements/current`
            );
            return {
              contents: [
                {
                  uri,
                  mimeType: 'application/json',
                  text: JSON.stringify(response.data, null, 2),
                },
              ],
            };
          }

          case 'company://team/members': {
            const response = await this.makeAuthenticatedRequest(
              `${process.env.PROJECT_API_BASE}/team/members`
            );
            return {
              contents: [
                {
                  uri,
                  mimeType: 'application/json',
                  text: JSON.stringify(response.data, null, 2),
                },
              ],
            };
          }

          default:
            throw new McpError(ErrorCode.InvalidRequest, `Unknown resource: ${uri}`);
        }
      } catch (error) {
        if (error instanceof McpError) throw error;
        
        console.error(`[${new Date().toISOString()}] Error reading resource ${uri}:`, error);
        throw new McpError(ErrorCode.InternalError, `Failed to read resource: ${uri}`);
      }
    });

    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'create_project',
            description: 'Create a new Company project',
            inputSchema: {
              type: 'object',
              properties: {
                name: { type: 'string', description: 'Project name' },
                description: { type: 'string', description: 'Project description' },
                team_lead: { type: 'string', description: 'Team lead email' },
                priority: { 
                  type: 'string', 
                  enum: ['low', 'medium', 'high', 'critical'],
                  description: 'Project priority'
                },
              },
              required: ['name', 'description', 'team_lead'],
            },
          },
          {
            name: 'update_requirement',
            description: 'Update a project requirement',
            inputSchema: {
              type: 'object',
              properties: {
                requirement_id: { type: 'string', description: 'Requirement ID' },
                status: { 
                  type: 'string', 
                  enum: ['draft', 'review', 'approved', 'implemented'],
                  description: 'Requirement status'
                },
                notes: { type: 'string', description: 'Update notes' },
              },
              required: ['requirement_id', 'status'],
            },
          },
        ],
      };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'create_project': {
            const response = await this.makeAuthenticatedRequest(
              `${process.env.PROJECT_API_BASE}/projects`,
              {
                method: 'POST',
                data: args,
              }
            );

            return {
              content: [
                {
                  type: 'text',
                  text: `Project "${args.name}" created successfully with ID: ${response.data.id}`,
                },
              ],
            };
          }

          case 'update_requirement': {
            const response = await this.makeAuthenticatedRequest(
              `${process.env.PROJECT_API_BASE}/requirements/${args.requirement_id}`,
              {
                method: 'PUT',
                data: {
                  status: args.status,
                  notes: args.notes,
                },
              }
            );

            return {
              content: [
                {
                  type: 'text',
                  text: `Requirement ${args.requirement_id} updated to status: ${args.status}`,
                },
              ],
            };
          }

          default:
            throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
        }
      } catch (error) {
        if (error instanceof McpError) throw error;
        
        console.error(`[${new Date().toISOString()}] Error calling tool ${name}:`, error);
        throw new McpError(ErrorCode.InternalError, `Tool execution failed: ${name}`);
      }
    });
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.log(`[${new Date().toISOString()}] Company Project Context MCP Server running`);
  }
}

// Start the server
const server = new CompanyProjectContextServer();
server.run().catch(console.error);
```

### 4. Package Configuration

**File**: `mcp-servers/company-project-context/package.json`

```json
{
  "name": "company-project-context-mcp",
  "version": "1.0.0",
  "description": "MCP server for Company project context and API integration",
  "main": "dist/index.js",
  "type": "module",
  "scripts": {
    "build": "tsc",
    "start": "node dist/index.js",
    "dev": "tsc --watch & nodemon dist/index.js"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^0.5.0",
    "axios": "^1.6.0"
  },
  "devDependencies": {
    "@types/node": "^20.0.0",
    "typescript": "^5.0.0",
    "nodemon": "^3.0.0"
  },
  "keywords": ["mcp", "company", "oauth", "context", "copilot"],
  "author": "Tristan Nolan <tnolan@company.com>",
  "license": "MIT"
}
```

## Environment Configuration

### Development Environment

**File**: `.env.development`

```bash
# OAuth Configuration
OAUTH_TOKEN_ENDPOINT=http://localhost:5000
OAUTH_CLIENT_ID=0oa8f5j3ecb5w3dF35d7
OAUTH_CLIENT_SECRET=a_very_secret_mock_value_for_alpha
OAUTH_SCOPES=mcp:projects:read mcp:projects:write

# API Configuration
PROJECT_API_BASE=https://dev-api.company.com/v1
CONFLUENCE_BASE_URL=https://company-dev.atlassian.net
CONFLUENCE_SPACE_KEY=DEV

# Logging
LOG_LEVEL=debug
MCP_DEBUG=true
```

### Production Environment

**File**: `.env.production`

```bash
# OAuth Configuration (use Azure Key Vault or similar for secrets)
OAUTH_TOKEN_ENDPOINT=https://login.company.com/oauth2/token
OAUTH_CLIENT_ID=0oa8f5j3ecb5w3dF35d7
OAUTH_CLIENT_SECRET=${KEY_VAULT_SECRET:oauth-client-secret}
OAUTH_SCOPES=mcp:projects:read mcp:projects:write

# API Configuration
PROJECT_API_BASE=https://api.company.com/v1
CONFLUENCE_BASE_URL=https://company.atlassian.net
CONFLUENCE_SPACE_KEY=NAV

# Logging
LOG_LEVEL=info
MCP_DEBUG=false
```

## GitHub Copilot Integration Prompts

### Custom Prompts for Enhanced Context

**File**: `.copilot/prompts/company-context.md`

````markdown
# Company Enterprise Development Context

## Project Standards
- Use .NET 8.0 for new backend services
- Follow Company coding standards and patterns
- Implement OAuth 2.0 for service-to-service authentication
- Use MCP servers for AI context integration

## Authentication Patterns
When implementing authentication:
1. Use OAuth 2.0 Client Credentials flow for service accounts
2. Implement proper token caching and renewal
3. Add comprehensive logging for security audit trails
4. Follow the patterns established in mcp-service-account-auth-example

## Code Generation Guidelines
- Generate code that integrates with existing Company APIs
- Include proper error handling and logging
- Follow established naming conventions
- Add appropriate unit tests and documentation

## Resources Available
- Company Project API: Access through MCP for current project data
- Team Directory: Real-time team member information
- Requirements Database: Current project requirements and specs
- Confluence Documentation: Enterprise knowledge base
````

## Usage Examples

### 1. GitHub Copilot with Project Context

When working in VS Code with the MCP server configured, GitHub Copilot will have access to:

```typescript
// Copilot can now suggest code based on actual Company project data
async function getCurrentProjectRequirements() {
  // Copilot knows about actual projects and can suggest relevant code
  const projects = await mcpClient.getResource('company://projects');
  const currentProject = projects.find(p => p.status === 'active');
  
  if (currentProject) {
    return await mcpClient.getResource(`company://requirements/${currentProject.id}`);
  }
}
```

### 2. Automated API Integration

```typescript
// Copilot can generate API calls based on real Company API schemas
async function createNewFeature(featureData: FeatureRequest) {
  // OAuth token handling is suggested based on MCP server patterns
  const authToken = await oauthService.getToken([
    'mcp:projects:write',
    'mcp:features:create'
  ]);
  
  return await projectApi.createFeature(featureData, {
    headers: { Authorization: `Bearer ${authToken}` }
  });
}
```

### 3. Documentation-Aware Code Generation

```csharp
// Copilot can reference actual Confluence documentation
/// <summary>
/// Implements the Company Project Creation pattern as documented in
/// https://company.atlassian.net/wiki/spaces/NAV/pages/...
/// 
/// This follows the OAuth 2.0 service account authentication model
/// established in the mcp-service-account-auth-example.
/// </summary>
public class ProjectService
{
    private readonly IOAuthTokenService _tokenService;
    
    public async Task<Project> CreateProjectAsync(CreateProjectRequest request)
    {
        // Implementation follows Company standards...
    }
}
```

## Monitoring and Debugging

### MCP Server Health Check

**File**: `scripts/mcp-health-check.ps1`

```powershell
# Health check script for MCP servers
param(
    [string]$ServerName = "company-project-context"
)

Write-Host "Checking MCP Server: $ServerName" -ForegroundColor Green

# Check if server process is running
$processes = Get-Process -Name "node" -ErrorAction SilentlyContinue | 
    Where-Object { $_.CommandLine -like "*$ServerName*" }

if ($processes) {
    Write-Host "✅ Server process is running" -ForegroundColor Green
} else {
    Write-Host "❌ Server process not found" -ForegroundColor Red
    exit 1
}

# Test OAuth token acquisition
try {
    $tokenResponse = Invoke-RestMethod -Uri "http://localhost:5000" -Method POST -Body @{
        client_id = "0oa8f5j3ecb5w3dF35d7"
        client_secret = "a_very_secret_mock_value_for_alpha"
        grant_type = "client_credentials"
        scope = "mcp:projects:read"
    }
    
    Write-Host "✅ OAuth token acquisition successful" -ForegroundColor Green
    Write-Host "Token expires in: $($tokenResponse.expires_in) seconds" -ForegroundColor Cyan
} catch {
    Write-Host "❌ OAuth token acquisition failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "✅ MCP Server health check passed" -ForegroundColor Green
```

### Log Analysis

**File**: `scripts/analyze-mcp-logs.ps1`

```powershell
# Analyze MCP server logs for authentication patterns
param(
    [string]$LogPath = "./auth.log",
    [int]$Days = 7
)

$cutoffDate = (Get-Date).AddDays(-$Days)
$logEntries = Get-Content $LogPath | Where-Object { 
    $_ -match '\[([\d-]+ [\d:]+)\]' -and [DateTime]::Parse($Matches[1]) -gt $cutoffDate 
}

# Count authentication attempts
$totalAttempts = ($logEntries | Where-Object { $_ -match "Authentication attempt" }).Count
$successfulAttempts = ($logEntries | Where-Object { $_ -match "Authentication successful" }).Count
$failedAttempts = $totalAttempts - $successfulAttempts

Write-Host "📊 Authentication Summary (Last $Days days):" -ForegroundColor Yellow
Write-Host "Total Attempts: $totalAttempts" -ForegroundColor White
Write-Host "Successful: $successfulAttempts" -ForegroundColor Green
Write-Host "Failed: $failedAttempts" -ForegroundColor Red

if ($totalAttempts -gt 0) {
    $successRate = [math]::Round(($successfulAttempts / $totalAttempts) * 100, 2)
    Write-Host "Success Rate: $successRate%" -ForegroundColor Cyan
}

# Most active clients
$clientUsage = $logEntries | Where-Object { $_ -match "client: (\w+)" } | 
    ForEach-Object { $Matches[1] } | Group-Object | Sort-Object Count -Descending

Write-Host "`n🔍 Top Clients:" -ForegroundColor Yellow
$clientUsage | Select-Object -First 5 | ForEach-Object {
    Write-Host "  $($_.Name): $($_.Count) requests" -ForegroundColor White
}
```

## Security Considerations

### 1. Token Security
- **Never commit OAuth client secrets** to version control
- Use secure storage (Azure Key Vault, AWS Secrets Manager) for production
- Implement token rotation policies (30-90 days)
- Monitor for unusual authentication patterns

### 2. Scope Management
- **Principle of least privilege**: Grant minimal required scopes
- Regularly audit and review granted permissions
- Implement scope-based access control in APIs
- Log all scope usage for security analysis

### 3. Network Security
- Use HTTPS for all OAuth token endpoints in production
- Implement rate limiting on authentication endpoints
- Monitor for brute force attacks
- Use network segmentation for internal services

### 4. Audit and Compliance
- Log all authentication events with timestamps
- Implement retention policies for audit logs
- Provide audit reports for compliance reviews
- Alert on security events and anomalies

## Troubleshooting Common Issues

### Issue: MCP Server Not Connecting

**Symptoms**: VS Code shows MCP server as "disconnected"

**Solutions**:
1. Check if the server process is running
2. Verify the command path in VS Code settings
3. Check environment variables are set correctly
4. Review server logs for startup errors

### Issue: OAuth Authentication Failures

**Symptoms**: "Failed to acquire authentication token" errors

**Solutions**:
1. Verify client credentials in environment variables
2. Check if the OAuth server is running (localhost:5000)
3. Validate the token endpoint URL
4. Ensure requested scopes are valid

### Issue: GitHub Copilot Not Using Context

**Symptoms**: Copilot suggestions don't reflect Company-specific data

**Solutions**:
1. Verify MCP servers are listed as "connected" in VS Code
2. Check that resources are being properly exposed
3. Restart VS Code to refresh MCP connections
4. Review MCP server logs for resource access errors

## Best Practices Summary

1. **Development Workflow**
   - Use mock OAuth server for local development
   - Implement comprehensive logging and monitoring
   - Test MCP server functionality independently
   - Document custom prompts and context patterns

2. **Production Deployment**
   - Use enterprise identity providers (Okta, Azure AD)
   - Implement proper secret management
   - Set up monitoring and alerting
   - Follow security and compliance requirements

3. **Team Collaboration**
   - Share MCP server configurations through version control
   - Document custom tools and resources
   - Establish coding standards for AI-assisted development
   - Train team members on MCP and OAuth patterns

4. **Continuous Improvement**
   - Monitor AI assistance effectiveness
   - Gather feedback on context quality
   - Iterate on MCP server capabilities
   - Maintain and update documentation

By implementing this MCP server configuration, development teams can leverage GitHub Copilot with rich, authenticated access to Company's project data, APIs, and documentation, significantly enhancing the AI-assisted development experience while maintaining enterprise security standards.
