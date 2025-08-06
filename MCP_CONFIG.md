# MCP Server Configuration for Visual Studio Code + GitHub Copilot

## Overview

This document provides a comprehensive configuration guide for integrating the OAuth 2.0 service account authentication system with **Model Context Protocol (MCP) servers** in Visual Studio Code and GitHub Copilot environments.

## What is MCP (Model Context Protocol)?

The **Model Context Protocol** is a standardized way for AI assistants (like GitHub Copilot) to securely access external data sources and services. MCP servers act as bridges between AI models and various APIs, databases, and services, providing contextual information that enhances code generation and assistance.

### Key Benefits of MCP Integration

- 🔗 **Seamless AI Integration**: Direct access to project data, documentation, and APIs
- 🔐 **Secure Authentication**: OAuth 2.0-based security for all AI-to-service communication
- 📊 **Rich Context**: AI assistants get real-time access to project state and requirements
- 🎯 **Scope-Based Permissions**: Fine-grained control over what data AI can access

## MCP Server Configuration

### 1. VS Code Settings Configuration

Create or update your VS Code settings to include MCP server configuration:

**File**: `.vscode/settings.json`

```json
{
  "mcp.servers": {
    "werner-project-context": {
      "command": "node",
      "args": [
        "/path/to/werner-mcp-server/dist/index.js"
      ],
      "env": {
        "OAUTH_TOKEN_ENDPOINT": "http://localhost:5000",
        "OAUTH_CLIENT_ID": "0oa8f5j3ecb5w3dF35d7",
        "OAUTH_SCOPES": "mcp:projects:read mcp:projects:write",
        "PROJECT_API_BASE": "https://api.werner.com/v1",
        "LOG_LEVEL": "info"
      },
      "capabilities": {
        "resources": true,
        "tools": true,
        "prompts": true
      }
    },
    "werner-documentation": {
      "command": "node",
      "args": [
        "/path/to/werner-docs-mcp/dist/index.js"
      ],
      "env": {
        "OAUTH_TOKEN_ENDPOINT": "http://localhost:5000",
        "OAUTH_CLIENT_ID": "0oa9g2k1idg9x7eE45d8",
        "OAUTH_SCOPES": "mcp:documentation:read",
        "CONFLUENCE_BASE_URL": "https://wernerent.atlassian.net",
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
  - name: "werner-project-context"
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
          url: "https://api.werner.com/v1/projects"
          methods: ["GET", "POST", "PUT"]
        - name: "requirements" 
          url: "https://api.werner.com/v1/requirements"
          methods: ["GET"]
      
  - name: "werner-documentation"
    type: "mcp-server"
    config:
      oauth:
        token_endpoint: "http://localhost:5000"
        client_id: "0oa9g2k1idg9x7eE45d8"
        scopes:
          - "mcp:documentation:read"
      endpoints:
        - name: "confluence"
          url: "https://wernerent.atlassian.net/wiki/rest/api"
          methods: ["GET"]
```

### 3. MCP Server Implementation Example

**File**: `mcp-servers/werner-project-context/src/index.ts`

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

class WernerProjectContextServer {
  private server: Server;
  private accessToken: string | null = null;
  private tokenExpires: Date | null = null;

  constructor() {
    this.server = new Server(
      {
        name: 'werner-project-context',
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
            uri: 'werner://projects',
            name: 'Active Projects',
            description: 'List of all active Werner projects',
            mimeType: 'application/json',
          },
          {
            uri: 'werner://requirements/current',
            name: 'Current Requirements',
            description: 'Current project requirements and specifications',
            mimeType: 'application/json',
          },
          {
            uri: 'werner://team/members',
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
          case 'werner://projects': {
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

          case 'werner://requirements/current': {
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

          case 'werner://team/members': {
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
            description: 'Create a new Werner project',
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
    console.log(`[${new Date().toISOString()}] Werner Project Context MCP Server running`);
  }
}

// Start the server
const server = new WernerProjectContextServer();
server.run().catch(console.error);
```

### 4. Package Configuration

**File**: `mcp-servers/werner-project-context/package.json`

```json
{
  "name": "werner-project-context-mcp",
  "version": "1.0.0",
  "description": "MCP server for Werner project context and API integration",
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
  "keywords": ["mcp", "werner", "oauth", "context", "copilot"],
  "author": "Tristan Nolan <tnolan@werner.com>",
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
PROJECT_API_BASE=https://dev-api.werner.com/v1
CONFLUENCE_BASE_URL=https://wernerent-dev.atlassian.net
CONFLUENCE_SPACE_KEY=DEV

# Logging
LOG_LEVEL=debug
MCP_DEBUG=true
```

### Production Environment

**File**: `.env.production`

```bash
# OAuth Configuration (use Azure Key Vault or similar for secrets)
OAUTH_TOKEN_ENDPOINT=https://login.werner.com/oauth2/token
OAUTH_CLIENT_ID=0oa8f5j3ecb5w3dF35d7
OAUTH_CLIENT_SECRET=${KEY_VAULT_SECRET:oauth-client-secret}
OAUTH_SCOPES=mcp:projects:read mcp:projects:write

# API Configuration
PROJECT_API_BASE=https://api.werner.com/v1
CONFLUENCE_BASE_URL=https://wernerent.atlassian.net
CONFLUENCE_SPACE_KEY=NAV

# Logging
LOG_LEVEL=info
MCP_DEBUG=false
```

## GitHub Copilot Integration Prompts

### Custom Prompts for Enhanced Context

**File**: `.copilot/prompts/werner-context.md`

````markdown
# Werner Enterprise Development Context

## Project Standards
- Use .NET 8.0 for new backend services
- Follow Werner coding standards and patterns
- Implement OAuth 2.0 for service-to-service authentication
- Use MCP servers for AI context integration

## Authentication Patterns
When implementing authentication:
1. Use OAuth 2.0 Client Credentials flow for service accounts
2. Implement proper token caching and renewal
3. Add comprehensive logging for security audit trails
4. Follow the patterns established in mcp-service-account-auth-example

## Code Generation Guidelines
- Generate code that integrates with existing Werner APIs
- Include proper error handling and logging
- Follow established naming conventions
- Add appropriate unit tests and documentation

## Resources Available
- Werner Project API: Access through MCP for current project data
- Team Directory: Real-time team member information
- Requirements Database: Current project requirements and specs
- Confluence Documentation: Enterprise knowledge base
````

## Usage Examples

### 1. GitHub Copilot with Project Context

When working in VS Code with the MCP server configured, GitHub Copilot will have access to:

```typescript
// Copilot can now suggest code based on actual Werner project data
async function getCurrentProjectRequirements() {
  // Copilot knows about actual projects and can suggest relevant code
  const projects = await mcpClient.getResource('werner://projects');
  const currentProject = projects.find(p => p.status === 'active');
  
  if (currentProject) {
    return await mcpClient.getResource(`werner://requirements/${currentProject.id}`);
  }
}
```

### 2. Automated API Integration

```typescript
// Copilot can generate API calls based on real Werner API schemas
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
/// Implements the Werner Project Creation pattern as documented in
/// https://wernerent.atlassian.net/wiki/spaces/NAV/pages/...
/// 
/// This follows the OAuth 2.0 service account authentication model
/// established in the mcp-service-account-auth-example.
/// </summary>
public class ProjectService
{
    private readonly IOAuthTokenService _tokenService;
    
    public async Task<Project> CreateProjectAsync(CreateProjectRequest request)
    {
        // Implementation follows Werner standards...
    }
}
```

## Monitoring and Debugging

### MCP Server Health Check

**File**: `scripts/mcp-health-check.ps1`

```powershell
# Health check script for MCP servers
param(
    [string]$ServerName = "werner-project-context"
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

**Symptoms**: Copilot suggestions don't reflect Werner-specific data

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

By implementing this MCP server configuration, development teams can leverage GitHub Copilot with rich, authenticated access to Werner's project data, APIs, and documentation, significantly enhancing the AI-assisted development experience while maintaining enterprise security standards.
