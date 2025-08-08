using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace mcp_service_account_auth_example.Pages
{
    public class GameDesignTeamAgentsModel : PageModel
    {
        private readonly ILogger<GameDesignTeamAgentsModel> _logger;

        public GameDesignTeamAgentsModel(ILogger<GameDesignTeamAgentsModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            _logger.LogInformation("GameDesignTeamAgents page accessed at {Time}", DateTime.UtcNow);
        }
    }
}
