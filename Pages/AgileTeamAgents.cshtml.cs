using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace mcp_service_account_auth_example.Pages
{
    public class AgileTeamAgentsModel : PageModel
    {
        private readonly ILogger<AgileTeamAgentsModel> _logger;

        public AgileTeamAgentsModel(ILogger<AgileTeamAgentsModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            _logger.LogInformation("AgileTeamAgents page accessed at {Time}", DateTime.UtcNow);
        }
    }
}
