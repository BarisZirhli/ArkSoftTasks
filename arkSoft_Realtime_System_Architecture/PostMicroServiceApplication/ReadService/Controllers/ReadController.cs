using Microsoft.AspNetCore.Mvc;
using ReadService.Services;
using System.Collections.Generic;
using System.Linq;

namespace ReadService.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class KafkaReadController : ControllerBase
    {
        private readonly KafkaReadService _kafkaReadService;
        private readonly IMessageQueueService _messageQueueService;
        public KafkaReadController(IMessageQueueService messageQueueService)
        {
            _messageQueueService = messageQueueService;
        }

        [HttpGet]
        public IActionResult GetMessages()
        {
            var messages = _messageQueueService.Messages.ToArray();
            return Ok(messages);
        }
    }
}
