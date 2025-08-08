using Microsoft.AspNetCore.Mvc.RazorPages;

namespace mcp_service_account_auth_example.Pages
{
    public class GitHubAzureWorkflowModel : PageModel
    {
        private readonly ILogger<GitHubAzureWorkflowModel> _logger;

        public GitHubAzureWorkflowModel(ILogger<GitHubAzureWorkflowModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            _logger.LogInformation("GitHub Azure Workflow page accessed at {Timestamp}", DateTime.UtcNow);
        }
    }
}
