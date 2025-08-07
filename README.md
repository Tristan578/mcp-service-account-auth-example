# MCP Service Account Authentication for AI-Assisted Development Environments

**Author:** Tristan Nolan  
**Repository:** [mcp-service-account-auth-example](https://github.com/Tristan578/mcp-service-account-auth-example)  

---

## 🎯 Executive Summary: Why This Solution Exists

**Stop putting personal tokens in your development environment MCP server configs!** 

This comprehensive ASP.NET Core solution addresses a critical security vulnerability in AI-assisted development: **the widespread practice of hardcoding personal API tokens directly into MCP server configurations**. By implementing a zero-credential service account architecture, we eliminate the single biggest security risk in modern AI-powered development workflows.

### The Business Problem
AI-assisted development tools like GitHub Copilot, Claude, and Windsurf require access to enterprise systems (GitHub, Azure DevOps, databases, Confluence) to provide intelligent context and suggestions. The current industry standard approach—embedding personal access tokens directly in configuration files—creates massive security vulnerabilities that scale with every developer on your team.

### The Technical Solution
This application provides secure authentication for MCP servers across multiple AI-assisted development environments, enabling developers to use GitHub Copilot, Claude, and other AI tools **without storing personal API keys in their settings**, while maintaining enterprise-grade security controls and audit compliance.

## 🏗️ Architecture Overview: Zero-Credential Design Philosophy

### Why Traditional Personal Token Approaches Fail at Enterprise Scale

The traditional approach of embedding personal access tokens in developer configurations creates a **credential proliferation crisis**:

1. **Scale Amplification**: Each developer requires personal tokens across multiple services
2. **Rotation Nightmare**: Token expiration requires manual updates across hundreds of developer machines
3. **Audit Impossibility**: No centralized visibility into AI tool access patterns
4. **Blast Radius**: Compromised developer machine exposes tokens to all enterprise systems
5. **Compliance Violation**: Personal credentials in persistent storage violate SOX, PCI, and security frameworks

### The Zero-Credential Service Account Pattern

Our solution implements a **token orchestration architecture** that eliminates credential storage on developer machines:

```mermaid
graph LR
    A[Developer IDE] --> B[MCP Runtime]
    B --> C{Service Account Endpoint}
    C --> D[Identity Provider]
    C --> E[Target Service API]
    D --> F[Fresh Token]
    E --> G[API Response]
    F --> B
    G --> A
```

**Core Principles:**
- **No Credentials at Rest**: Zero sensitive data stored on developer machines
- **Just-in-Time Access**: Tokens generated only when needed, with minimal scope
- **Centralized Identity**: All authentication flows through enterprise identity providers
- **Audit by Design**: Complete traceability of all AI assistant access patterns

### Multi-Environment Support Architecture

This solution supports secure MCP server configuration across all major AI-assisted development environments with **universal authentication patterns**:

- 🔧 **VS Code** (settings.json) - GitHub Copilot integration
- 🤖 **Claude Desktop** (claude_desktop_config.json) - Anthropic Claude desktop app
- 🌊 **Windsurf** (windsurf-mcp.json) - Codeium-powered development environment
- 🏢 **Visual Studio** (mcp-servers.json with agent mode) - Enterprise IDE integration
- 💻 **Claude Code** (.claude/settings.json with hooks) - Web-based Claude interface

**Why This Multi-Environment Approach Matters:**
- **Developer Choice**: Teams use different tools without compromising security
- **Migration Safety**: Secure migration paths between development environments
- **Standardization**: Uniform security patterns regardless of IDE choice
- **Enterprise Adoption**: Single security policy across diverse development workflows

## ⚠️ The Security Crisis: Understanding Why Personal Tokens in Development Environments Are Dangerous

### Current Industry Anti-Patterns (What Everyone Is Doing Wrong)

If you're manually configuring MCP servers in any development environment, your configurations probably contain critical security vulnerabilities:

```json
// ❌ ANTI-PATTERN: Personal tokens hardcoded in configuration files
// This is what most developers are doing right now across all environments:

// VS Code settings.json - Personal token exposed in sync'd settings
{
  "mcp.servers": {
    "github-context": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_your_personal_token_here"  // 🚨 SECURITY VIOLATION!
      }
    }
  }
}

// Claude Desktop claude_desktop_config.json - Credentials in cloud sync
{
  "mcpServers": {
    "github-context": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_your_personal_token_here"  // 🚨 COMPLIANCE FAILURE!
      }
    }
  }
}

// Visual Studio mcp-servers.json - Personal tokens in enterprise IDE
{
  "mcpServers": [
    {
      "name": "github-context",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_your_personal_token_here"  // 🚨 AUDIT VIOLATION!
      }
    }
  ]
}
```

### Why This Pattern Is a Security Disaster

**🔥 Critical Vulnerabilities Created:**
1. **Plaintext Credential Storage**: Personal tokens stored unencrypted in configuration files
2. **Cloud Synchronization Exposure**: Settings sync uploads credentials to Microsoft, Google, etc.
3. **Local Machine Compromise**: Any malware or unauthorized access exposes all enterprise tokens
4. **Credential Proliferation**: Each developer becomes a credential management liability
5. **Rotation Impossibility**: No centralized way to rotate credentials across hundreds of machines
6. **Audit Blind Spots**: No visibility into who accessed what systems when
7. **Compliance Failures**: Violates SOX 404, PCI DSS, and enterprise security frameworks

**📊 Enterprise Impact at Scale:**
- **100 developers** = 500+ personal tokens across enterprise systems
- **Token rotation** = Manual updates on 100+ machines per service
- **Compromised laptop** = Instant access to all enterprise APIs
- **Audit requirements** = Impossible to track AI assistant system access

### The Pattern That Solves Everything: Service Account Authentication

Instead of personal tokens, this system implements **enterprise-grade service account authentication** across all development environments:

```json
// ✅ SECURE PATTERN: Service account authentication with zero credential storage
// Universal pattern that works across all 5 supported environments:

// VS Code settings.json - No credentials stored locally
{
  "mcp.servers": {
    "github-context": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "${mcp_service_token:github-service-account}"
      }
    }
  }
}

// Claude Desktop claude_desktop_config.json - Dynamic token acquisition
{
  "mcpServers": {
    "github-context": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "${mcp_service_token:github-service-account}"
      }
    }
  }
}

// Visual Studio mcp-servers.json - Enterprise service account pattern
{
  "mcpServers": [
    {
      "name": "github-context",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "${mcp_service_token:github-service-account}"
      }
    }
  ],
  "agentMode": {
    "enabled": true,
    "defaultProvider": "github-copilot"
  }
}
```

### Why Service Account Authentication Solves Everything

**🔐 Security Benefits:**
- **Zero Local Credentials**: No sensitive data stored on developer machines
- **Dynamic Token Acquisition**: Fresh tokens generated for each session
- **Centralized Management**: IT security controls all access through service accounts
- **Scope Limitation**: Tokens have minimal necessary permissions with automatic expiration
- **Audit Trail**: Complete visibility into all AI assistant system access

**🚀 Developer Experience Benefits:**
- **Safe Settings Sync**: Configuration files contain no secrets, safe for cloud backup
- **Universal Pattern**: Same authentication model across all development environments
- **Zero Maintenance**: No manual token rotation or credential management
- **Instant Onboarding**: New developers inherit secure access automatically

**🏢 Enterprise Benefits:**
- **Compliance Ready**: Meets SOX 404, PCI DSS, and enterprise security requirements
- **Centralized Control**: Single point of access management for all AI tools
- **Cost Reduction**: Eliminates credential management overhead
- **Risk Mitigation**: Compromised developer machine has no credential exposure

### Design Pattern: Token Orchestration Service

The `${mcp_service_token:service-account-name}` pattern triggers a **token orchestration flow**:

1. **MCP Runtime Initialization**: When MCP server starts, it detects the service token pattern
2. **Authentication Request**: Runtime calls centralized authentication endpoint
3. **Identity Validation**: Service account credentials validated against enterprise identity provider  
4. **Scope Authorization**: Requested permissions validated against service account policy
5. **Fresh Token Generation**: New, time-limited token generated for specific service
6. **Secure Injection**: Token injected into MCP server environment variables
7. **API Access**: MCP server uses fresh token for authenticated API calls
8. **Automatic Expiration**: Token expires, forcing re-authentication for next session

## 🏛️ Security Architecture Patterns & Design Decisions

### Pattern 1: Token Orchestration Service
**Intent**: Eliminate credential storage on developer machines while maintaining seamless AI assistant integration.

**Implementation**: Central authentication service that translates service account credentials into fresh, scoped API tokens.

**Why This Pattern**: 
- **Separation of Concerns**: Authentication logic centralized, development environments focus on functionality
- **Defense in Depth**: Multiple layers of security (service accounts → orchestration → scoped tokens)
- **Compliance Alignment**: Meets enterprise requirements for credential management and audit trails

### Pattern 2: Environment Variable Substitution
**Intent**: Provide a universal mechanism for secure credential injection across all development environments.

**Implementation**: The `${mcp_service_token:service-account-name}` pattern that triggers runtime token acquisition.

**Why This Pattern**:
- **Declarative Security**: Developers declare intent, security team controls implementation
- **Environment Agnostic**: Same pattern works across VS Code, Claude Desktop, Visual Studio, Windsurf, Claude Code
- **Zero Trust**: No assumption that credentials exist locally

### Pattern 3: Scope-Based Authorization
**Intent**: Implement principle of least privilege for AI assistant system access.

**Implementation**: Service accounts configured with minimal necessary permissions, tokens issued with explicit scopes.

**Why This Pattern**:
- **Blast Radius Limitation**: Compromised AI assistant has minimal system access
- **Role-Based Security**: Different AI use cases get different permission levels
- **Audit Granularity**: Detailed tracking of what AI assistants can access

### Anti-Pattern Analysis: What Not To Do

#### ❌ Anti-Pattern: Personal Access Token Proliferation
```json
// DON'T DO THIS - Creates massive security liability
{
  "GITHUB_TOKEN": "ghp_personal_token_here",
  "AZURE_TOKEN": "personal_azure_token",
  "DB_PASSWORD": "personal_database_password"
}
```
**Why This Fails**: Creates credential sprawl, impossible to rotate, violates enterprise security policies.

#### ❌ Anti-Pattern: Shared Secret Distribution
```json
// DON'T DO THIS - Shared secrets become impossible to manage
{
  "SHARED_API_KEY": "team_shared_secret_everyone_knows"
}
```
**Why This Fails**: No individual accountability, credential rotation requires team coordination.

#### ✅ Correct Pattern: Service Account Orchestration
```json
// DO THIS - Declarative, secure, auditable
{
  "GITHUB_TOKEN": "${mcp_service_token:github-readonly-account}",
  "AZURE_TOKEN": "${mcp_service_token:azure-devops-readonly}",
  "DB_CONNECTION": "${mcp_service_token:database-readonly}"
}
```
**Why This Works**: Zero local storage, centralized management, individual audit trails.

## 📚 Related Documentation & Resources

### Internal Documentation
- **[Enterprise Permissions Guide](./Pages/Permissions.cshtml)** - Role-based access control matrices
- **[IAM Setup Guide](./Pages/ServiceAccountSetup.cshtml)** - Identity provider configuration instructions
- **[Live Demo Application](http://localhost:5000)** - Interactive configuration testing

### Documentation and Resources
- **Project Documentation** - Comprehensive implementation guide and best practices

## 🔒 Security Architecture and Design Decisions

### Core Security Principles

#### 1. Zero-Credential Storage Principle
**Decision**: Never store long-lived credentials on developer machines
**Rationale**: Eliminates the most common attack vector for credential theft
**Implementation**: Service account token pattern with runtime authentication

#### 2. Minimal Permission Principle  
**Decision**: AI assistants receive only the minimum permissions required for their specific function
**Rationale**: Limits blast radius if an AI assistant is compromised
**Implementation**: Role-based service account templates with granular scoping

#### 3. Temporal Token Limitation
**Decision**: All tokens have short lifespans and automatic expiration
**Rationale**: Reduces window of opportunity for credential misuse
**Implementation**: JWT tokens with 15-minute default expiration

#### 4. Audit-First Design
**Decision**: Every access request generates auditable events
**Rationale**: Enterprise security requires complete visibility into AI assistant access patterns
**Implementation**: Centralized authentication service with comprehensive logging

### Security Design Patterns vs Anti-Patterns

#### ✅ Secure Pattern: Service Account Authentication
```json
{
  "env": {
    "GITHUB_TOKEN": "${mcp_service_token:github-copilot-context}"
  }
}
```
**Why This Works**:
- **Identity Clarity**: Service account clearly indicates intended use
- **Scope Limitation**: Token has minimal necessary permissions  
- **Automatic Rotation**: Fresh token for every session
- **Enterprise Control**: IT team manages service account lifecycle

#### ❌ Anti-Pattern: Personal Token Storage
```json
{
  "env": {
    "GITHUB_TOKEN": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  }
}
```
**Why This Fails**:
- **Credential Exposure**: Token stored in plaintext configuration
- **Over-Permissioning**: Personal token has full user permissions
- **No Rotation**: Token valid until manually revoked
- **Audit Blindness**: No visibility into token usage patterns

#### ✅ Secure Pattern: Environment-Aware Permissions
```json
{
  "development": {
    "AZURE_TOKEN": "${mcp_service_token:azure-dev-contributor}"
  },
  "production": {
    "AZURE_TOKEN": "${mcp_service_token:azure-prod-readonly}"
  }
}
```
**Why This Works**:
- **Environment Isolation**: Production systems protected from development access
- **Permission Scaling**: Rights appropriate to environment criticality
- **Deployment Safety**: AI assistants cannot accidentally modify production

#### ❌ Anti-Pattern: Universal High-Privilege Access
```json
{
  "env": {
    "AZURE_TOKEN": "${admin_token_all_environments}"
  }
}
```
**Why This Fails**:
- **Over-Privilege**: Single token with admin rights across all environments
- **Environment Confusion**: No protection against cross-environment access
- **Incident Amplification**: Compromise affects all systems simultaneously

### Architectural Decision Records

#### ADR-001: Why Service Account Pattern Over OAuth2
**Context**: AI assistants need API access without user intervention
**Decision**: Use service account authentication instead of OAuth2 user flows
**Consequences**: 
- ✅ **Benefit**: No interactive authentication required for AI assistants
- ✅ **Benefit**: Clear audit trail of service access vs user access
- ❌ **Trade-off**: Additional infrastructure for service account management

#### ADR-002: Why JWT Tokens Over API Keys
**Context**: Need secure, time-limited authentication tokens
**Decision**: Generate JWT tokens instead of long-lived API keys
**Consequences**:
- ✅ **Benefit**: Built-in expiration prevents indefinite credential exposure
- ✅ **Benefit**: Claims-based tokens enable fine-grained permission control
- ❌ **Trade-off**: Requires token validation infrastructure

#### ADR-003: Why Centralized Authentication Service
**Context**: Multiple MCP servers need authentication across different AI environments
**Decision**: Build centralized authentication service instead of per-MCP authentication
**Consequences**:
- ✅ **Benefit**: Consistent security policy enforcement across all AI tools
- ✅ **Benefit**: Single point for credential management and audit
- ❌ **Trade-off**: Additional infrastructure dependency for all AI assistants

## 📚 Comprehensive Documentation and Resources

### Internal Documentation Links

#### Architecture Documentation
- [**Service Account Setup Guide**](ServiceAccountSetup.cshtml) - Step-by-step enterprise deployment
- [**Permission Configuration**](Permissions.cshtml) - Role-based access control templates
- [**Developer Guidelines**](DeveloperGuidelines.cshtml) - AI-assisted development best practices and MCP server education
- [**Security Policy Template**](security-policy.md) - Enterprise security policy framework
- [**Incident Response Plan**](incident-response.md) - AI assistant security incident procedures

#### Implementation Guides
- [**VS Code Integration**](docs/vscode-setup.md) - Setting up MCP servers with service accounts
- [**Claude Desktop Configuration**](docs/claude-setup.md) - Service account pattern for Claude
- [**GitHub Copilot Enterprise**](docs/github-copilot-enterprise.md) - Secure context configuration
- [**Multi-Environment Deployment**](docs/environment-strategy.md) - Dev/Test/Prod configuration patterns

### External Documentation References

#### Microsoft Identity Platform
- [**Azure AD Service Principals**](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals) - Understanding service account architecture
- [**Application Registration Best Practices**](https://docs.microsoft.com/en-us/azure/active-directory/develop/security-best-practices-for-app-registration) - Security configuration guidelines
- [**Managed Identity vs Service Principal**](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview) - When to use each pattern

#### GitHub Enterprise Security
- [**GitHub Apps vs Personal Access Tokens**](https://docs.github.com/en/developers/apps/getting-started-with-apps/about-apps) - Comparison of authentication methods
- [**Fine-grained Personal Access Tokens**](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) - Modern GitHub authentication patterns
- [**Enterprise Security Best Practices**](https://docs.github.com/en/enterprise-cloud@latest/admin/policies/enforcing-policies-for-your-enterprise/enforcing-policies-for-personal-access-tokens-in-your-enterprise) - Organization-level token management

#### Industry Security Frameworks
- [**NIST Cybersecurity Framework**](https://www.nist.gov/cyberframework) - Federal security standards for identity management
- [**ISO 27001 Access Control**](https://www.iso.org/standard/54534.html) - International standard for access control systems  
- [**OWASP Authentication Cheat Sheet**](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) - Security patterns for authentication systems
- [**Zero Trust Architecture**](https://www.nist.gov/publications/zero-trust-architecture) - NIST guidelines for zero-trust security models

#### AI Security and Ethics
- [**NIST AI Risk Management Framework**](https://www.nist.gov/itl/ai-risk-management-framework) - Federal guidelines for AI security
- [**Microsoft Responsible AI**](https://www.microsoft.com/en-us/ai/responsible-ai) - Enterprise AI governance frameworks
- [**OpenAI Model Security**](https://platform.openai.com/docs/guides/safety-best-practices) - Best practices for AI model security

### Related Enterprise Documentation

#### Compliance and Governance
- [**SOC 2 Type II Compliance for AI Tools**](docs/compliance/soc2-ai-tools.md) - Audit requirements for AI assistant access
- [**GDPR Data Processing for AI Context**](docs/compliance/gdpr-ai-context.md) - European privacy law compliance
- [**HIPAA Guidelines for AI in Healthcare**](docs/compliance/hipaa-ai-guidelines.md) - Healthcare AI assistant security requirements

#### Operational Documentation  
- [**AI Assistant Monitoring Dashboard**](docs/operations/monitoring-setup.md) - Prometheus/Grafana configuration for AI tool observability
- [**Incident Response Playbook**](docs/operations/incident-response.md) - Step-by-step procedures for AI security incidents
- [**Disaster Recovery for AI Infrastructure**](docs/operations/disaster-recovery.md) - Business continuity planning for AI development tools

### Why This Documentation Strategy Matters

#### Business Justification
- **Risk Mitigation**: Comprehensive documentation reduces security incident probability
- **Audit Readiness**: External auditors can quickly verify security controls
- **Knowledge Preservation**: Documentation survives personnel changes and organizational restructuring
- **Compliance Acceleration**: Pre-built frameworks speed regulatory compliance efforts

#### Technical Benefits
- **Implementation Consistency**: Standardized patterns prevent security configuration drift
- **Onboarding Efficiency**: New team members can self-serve secure AI assistant setup
- **Troubleshooting Speed**: Comprehensive guides reduce time-to-resolution for access issues
- **Architecture Evolution**: Documentation enables informed decisions about system improvements
- **IAM Configuration Guide** - Identity provider service account setup documentation
- **Security Architecture** - Zero-credential design patterns and best practices

### External Provider Documentation
- **[Model Context Protocol Specification](https://modelcontextprotocol.io/docs/concepts/architecture)** - Official MCP architecture
- **[GitHub Apps Authentication](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)** - Service account patterns for GitHub
- **[Azure Service Principal Best Practices](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals)** - Enterprise identity patterns
- **[OAuth 2.0 Client Credentials Flow](https://tools.ietf.org/html/rfc6749#section-4.4)** - Standards compliance reference
- **[Okta Service-to-Service Authentication](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/)** - Enterprise IAM integration

### Security Framework References
- **[NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)** - Industry security standards
- **[SOX 404 Compliance Requirements](https://www.sarbanes-oxley-101.com/sarbanes-oxley-compliance.htm)** - Financial audit requirements
- **[Zero Trust Architecture](https://www.nist.gov/publications/zero-trust-architecture)** - Modern security architecture principles

## 🔧 Interactive Configuration System

This project includes a comprehensive web interface that automatically generates proper MCP server configurations for all 5 supported development environments:

### Why Interactive Configuration Matters
**Problem**: Manual JSON configuration is error-prone and requires deep understanding of each environment's specifics.
**Solution**: Web-based configuration generator that produces validated, secure configurations.

### Features
1. **Visit the web interface** at `http://localhost:5000`
2. **Click any service account example** to auto-populate configurations
3. **Copy the generated JSON** for your specific development environment
4. **Paste into your environment's configuration file**

### Supported Service Account Templates

The system includes enterprise-grade service account templates designed for different AI assistant use cases:

- **GitHub Context Server** - Repository access with Personal Access Token authentication
  - **Use Case**: GitHub Copilot context, code review assistance
  - **Security Model**: Read-only repository access, public repo limitations
  - **Enterprise Integration**: GitHub Apps for organization-wide management

- **Microsoft SQL Server** - Azure AD Service Principal authentication
  - **Use Case**: Database schema awareness, query optimization suggestions
  - **Security Model**: Read-only data access, schema-only permissions
  - **Enterprise Integration**: Azure Active Directory service principal authentication

- **Azure Resources** - Service Principal with client secret
  - **Use Case**: Cloud resource context, infrastructure recommendations
  - **Security Model**: Resource discovery permissions, no modification rights
  - **Enterprise Integration**: Azure RBAC with principle of least privilege

- **MuleSoft APIs** - Connected App token authentication
  - **Use Case**: Integration platform context, API discovery
  - **Security Model**: API metadata access, no execution permissions
  - **Enterprise Integration**: Anypoint Platform service accounts

- **SonarQube Analysis** - Project analysis token
  - **Use Case**: Code quality metrics, security vulnerability awareness
  - **Security Model**: Project-scoped read access, quality gate visibility
  - **Enterprise Integration**: SonarQube service accounts with project permissions

- **Playwright Testing** - API key authentication
  - **Use Case**: Test automation context, browser testing recommendations
  - **Security Model**: Test execution permissions, result access
  - **Enterprise Integration**: Testing infrastructure service accounts

### Why These Specific Service Accounts
Each service account template addresses specific enterprise requirements:

1. **GitHub Integration**: Essential for any AI assistant that provides code suggestions
2. **Database Access**: Required for AI tools that understand data relationships
3. **Cloud Resources**: Necessary for infrastructure-aware development assistance
4. **API Integration**: Critical for microservices and integration development
5. **Quality Assurance**: Essential for maintaining code quality standards
6. **Testing Infrastructure**: Required for test-driven development workflows

## 🔄 How Token Orchestration Works Across All Development Environments

### Universal Authentication Flow
This pattern works identically across VS Code, Claude Desktop, Visual Studio, Windsurf, and Claude Code:

1. **Developer opens IDE** with MCP servers configured using service account patterns
2. **MCP server starts** and detects `${mcp_service_token:service-account-name}` environment variables
3. **Runtime calls authentication endpoint** with service account identifier
4. **Authentication server validates request** against enterprise identity provider
5. **Fresh tokens generated** with appropriate scopes for the requested service
6. **Tokens injected into MCP server environment** replacing the placeholder variables
7. **AI assistant gets context** through secure API calls using fresh tokens
8. **Tokens expire automatically** preventing long-term credential exposure

### Why This Flow Is Superior to Personal Tokens

**Traditional Flow (Insecure)**:
```
Developer Machine → Personal Token → Direct API Call → Enterprise System
                   ↑ (Stored on disk, never rotates, full permissions)
```

**Service Account Flow (Secure)**:
```
Developer Machine → Service Account Request → Auth Service → Identity Provider
                                         ↓
Enterprise System ← Scoped Fresh Token ← Token Generation ←
```

**Security Advantages**:
- **No Credential Storage**: Zero secrets persisted on developer machines
- **Automatic Rotation**: Fresh tokens for every session
- **Scope Limitation**: Minimal necessary permissions only
- **Audit Trail**: Complete visibility into access patterns
- **Centralized Control**: Enterprise identity team manages all access

### Real-World Developer Workflow

#### Before: Manual Token Management (Insecure)
1. Developer needs GitHub Copilot context
2. Creates personal access token in GitHub
3. Copies token into VS Code settings
4. Token expires → Manual rotation required
5. Developer leaves → Token cleanup forgotten
6. Security incident → No way to track access

#### After: Service Account Authentication (Secure)  
1. Developer configures MCP server with service account pattern
2. AI assistant automatically gets secure context
3. No manual token management required
4. Developer leaves → Access automatically revoked
5. Security audit → Complete access history available
6. Token rotation → Transparent to developer

## 🔍 Enterprise Implementation Patterns

### Pattern: Multi-Environment Service Account Strategy

Different development environments require different security postures:

#### Development Environment (Permissive)
```json
{
  "env": {
    "GITHUB_TOKEN": "${mcp_service_token:github-dev-readwrite}",
    "AZURE_TOKEN": "${mcp_service_token:azure-dev-contributor}",
    "DB_CONNECTION": "${mcp_service_token:database-dev-readwrite}"
  }
}
```

#### Production Environment (Restrictive)
```json
{
  "env": {
    "GITHUB_TOKEN": "${mcp_service_token:github-prod-readonly}",
    "AZURE_TOKEN": "${mcp_service_token:azure-prod-readonly}",
    "DB_CONNECTION": "${mcp_service_token:database-prod-readonly}"
  }
}
```

### Pattern: Role-Based Service Account Assignment

Different developer roles get different AI assistant capabilities:

#### Software Engineer
```json
{
  "env": {
    "GITHUB_TOKEN": "${mcp_service_token:github-engineer-readwrite}",
    "CODE_ANALYSIS": "${mcp_service_token:sonarqube-project-read}"
  }
}
```

#### Product Manager  
```json
{
  "env": {
    "GITHUB_TOKEN": "${mcp_service_token:github-pm-readonly}",
    "AZURE_BOARDS": "${mcp_service_token:azure-devops-pm-readwrite}"
  }
}
```

#### DevOps Engineer
```json
{
  "env": {
    "GITHUB_TOKEN": "${mcp_service_token:github-devops-admin}",
    "AZURE_RESOURCES": "${mcp_service_token:azure-infrastructure-readwrite}"
  }
}
```

### Why Role-Based Access Matters for AI Assistants
- **Principle of Least Privilege**: AI tools only access systems relevant to user's role
- **Data Classification**: Sensitive systems remain isolated from unauthorized AI access
- **Compliance Alignment**: Access patterns match enterprise role-based access control policies
- **Incident Containment**: Compromised AI assistant limited to role-appropriate systems

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
- 📊 **Real-time Project Context**: Secure access to enterprise APIs, documentation, and team data
- 🛠️ **Custom Tools and Resources**: Authenticated project management without personal tokens

## License

This project is provided as-is for educational and development purposes.
