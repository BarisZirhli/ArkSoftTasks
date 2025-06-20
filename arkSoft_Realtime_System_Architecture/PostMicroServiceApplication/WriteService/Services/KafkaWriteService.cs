using Confluent.Kafka;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;
using WriteService.Data;
using WriteService.Model;

namespace WriteService.Services
{
    public class KafkaWriteService : IDisposable
    {
        private readonly IProducer<Null, string> _producer;
        private readonly ILogger<KafkaWriteService> _logger;
        private readonly IServiceScopeFactory _scopeFactory;

        public KafkaWriteService(IConfiguration config, ILogger<KafkaWriteService> logger, IServiceScopeFactory scopeFactory)
        {
            _logger = logger;
            _scopeFactory = scopeFactory;

            var producerConfig = new ProducerConfig
            {
                BootstrapServers = "kafka:9092",
                MessageTimeoutMs = 5000,
                RequestTimeoutMs = 3000
            };

            _producer = new ProducerBuilder<Null, string>(producerConfig)
                .SetErrorHandler((_, e) => _logger.LogError($"Kafka error: {e.Reason}"))
                .Build();
        }

        public async Task SendMessageAsync(string topic, string message)
        {
            try
            {
                var result = await _producer.ProduceAsync(topic, new Message<Null, string> { Value = message });
                _logger.LogInformation($"Delivered message to {result.TopicPartitionOffset}");

                using (var scope = _scopeFactory.CreateScope())
                {
                    var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();

                    var kafkaMessage = new Post
                    {
                        PostContent = message
                    };

                    dbContext.Add(kafkaMessage);
                    await dbContext.SaveChangesAsync();
                }
            }
            catch (ProduceException<Null, string> e)
            {
                _logger.LogError($"Delivery failed: {e.Error.Reason}");
                throw;
            }
        }

        public void Dispose()
        {
            _producer?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
