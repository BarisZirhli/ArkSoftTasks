using Microsoft.AspNetCore.Mvc;
using WriteService.Model;
using WriteService.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using System;
using System.Threading.Tasks;

namespace WriteService.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class WriteController : ControllerBase
    {
        private readonly KafkaWriteService _writeService;
        private readonly ILogger<WriteController> _logger;
        private readonly string _topic;

        public WriteController(KafkaWriteService writeService, ILogger<WriteController> logger, IConfiguration config)
        {
            _writeService = writeService;
            _logger = logger;
            _topic = config["Kafka:Topic"] ?? "data-events";
        }

        [HttpPost]
        public async Task<IActionResult> Post([FromBody] Post model)
        {
            try
            {
                if (!ModelState.IsValid || string.IsNullOrWhiteSpace(model.PostContent))
                    return BadRequest("Invalid post data.");

                await _writeService.SendMessageAsync(_topic, model.PostContent);
                _logger.LogInformation($"Kafka mesajı gönderildi: {model.PostContent}");
                return Accepted(new { model.PostId, model.CreatedAt });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending message to Kafka");
                return StatusCode(500, "Internal server error");
            }
        }
    }
}
