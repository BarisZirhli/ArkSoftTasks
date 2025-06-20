using Confluent.Kafka;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ReadService.Data;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;

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
        private readonly IServiceScopeFactory _scopeFactory;
        private IConsumer<Ignore, string> _consumer;

        public KafkaReadService(
            ILogger<KafkaReadService> logger,
            IMessageQueueService messageQueueService,
            IServiceScopeFactory scopeFactory)
        {
            _logger = logger;
            _messageQueueService = messageQueueService;
            _scopeFactory = scopeFactory;

            var consumerConfig = new ConsumerConfig
            {
                BootstrapServers = "kafka:9092",
                GroupId = "read-service-group",
                AutoOffsetReset = AutoOffsetReset.Earliest
            };

            _consumer = new ConsumerBuilder<Ignore, string>(consumerConfig).Build();
            _consumer.Subscribe("data-events");
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var consumeResult = _consumer.Consume(stoppingToken);
                    if (consumeResult != null)
                    {
                        _logger.LogInformation($"Consumed: {consumeResult.Message.Value}");
                        _messageQueueService.Messages.Enqueue(consumeResult.Message.Value);

                        using (var scope = _scopeFactory.CreateScope())
                        {
                            var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();

                            // Örnek: KafkaMessageEntity oluşturup veritabanına ekle
                            var entity = new Model.Post
                            {
                                PostContent = consumeResult.Message.Value,
                                
                            };

                            dbContext.Add(entity);
                            await dbContext.SaveChangesAsync(stoppingToken);
                        }
                    }
                }
                catch (ConsumeException ex)
                {
                    _logger.LogError($"Consume error: {ex.Error.Reason}");
                }
                catch (OperationCanceledException)
                {
                    break; // Graceful shutdown
                }
            }
        }

        public override void Dispose()
        {
            _consumer?.Close();
            _consumer?.Dispose();
            base.Dispose();
        }
    }

   
}
