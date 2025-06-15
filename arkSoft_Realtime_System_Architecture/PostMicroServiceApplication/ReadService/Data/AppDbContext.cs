using Microsoft.EntityFrameworkCore;
using ReadService.Model;

namespace ReadService.Data
{
    public class AppDbContext:DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }
        public DbSet<Post> Posts { get; set; }
    }
    
}
