using System.Collections.Concurrent;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Confluent.Kafka;
using System.Threading;
using System.Threading.Tasks;

namespace ReadService.Services
{
    public interface IMessageQueueService
    {
        ConcurrentQueue<string> Messages { get; }
    }

    public class MessageQueueService : IMessageQueueService
    {
        public ConcurrentQueue<string> Messages { get; } = new ConcurrentQueue<string>();
    }

    public class KafkaReadService : BackgroundService
    {
        private readonly ILogger<KafkaReadService> _logger;
        private readonly IMessageQueueService _messageQueueService;
        private IConsumer<Ignore, string> _consumer;

        public KafkaReadService(ILogger<KafkaReadService> logger, IMessageQueueService messageQueueService)
        {
            _logger = logger;
            _messageQueueService = messageQueueService;

            var consumerConfig = new ConsumerConfig
            {
                BootstrapServers = "kafka:9092",
                GroupId = "read-service-group",
                AutoOffsetReset = AutoOffsetReset.Earliest
            };

            _consumer = new ConsumerBuilder<Ignore, string>(consumerConfig).Build();
            _consumer.Subscribe("data-events");
        }

        protected override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            return Task.Run(() =>
            {
                while (!stoppingToken.IsCancellationRequested)
                {
                    try
                    {
                        var consumeResult = _consumer.Consume(TimeSpan.FromMilliseconds(1000));
                        if (consumeResult != null)
                        {
                            _logger.LogInformation($"Consumed: {consumeResult.Message.Value}");
                            _messageQueueService.Messages.Enqueue(consumeResult.Message.Value);
                        }
                    }
                    catch (ConsumeException ex)
                    {
                        _logger.LogError($"Consume error: {ex.Error.Reason}");
                    }
                }
            }, stoppingToken);
        }

        public override void Dispose()
        {
            _consumer?.Close();
            _consumer?.Dispose();
            base.Dispose();
        }
    }
}
