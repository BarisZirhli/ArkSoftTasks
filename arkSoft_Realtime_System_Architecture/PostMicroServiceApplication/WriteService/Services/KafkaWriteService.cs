using Confluent.Kafka;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace WriteService.Services
{
    public class KafkaWriteService : IDisposable
    {
        private readonly IProducer<Null, string> _producer;
        private readonly ILogger<KafkaWriteService> _logger;

        public KafkaWriteService(IConfiguration config, ILogger<KafkaWriteService> logger)
        {
            _logger = logger;
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