using System.Collections.Concurrent;

namespace ReadService.Services
{
    public interface IMessageQService
    {
        ConcurrentQueue<string> Messages { get; }
    }

    public class MessageQService : IMessageQueueService
    {
        public ConcurrentQueue<string> Messages { get; } = new ConcurrentQueue<string>();
    }

}
