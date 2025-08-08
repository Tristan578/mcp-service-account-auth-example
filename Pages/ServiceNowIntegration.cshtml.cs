using Microsoft.AspNetCore.Mvc.RazorPages;

namespace mcp_service_account_auth_example.Pages
{
    public class ServiceNowIntegrationModel : PageModel
    {
        private readonly ILogger<ServiceNowIntegrationModel> _logger;

        public ServiceNowIntegrationModel(ILogger<ServiceNowIntegrationModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            _logger.LogInformation("ServiceNow Integration page accessed at {Timestamp}", DateTime.UtcNow);
        }
    }
}
