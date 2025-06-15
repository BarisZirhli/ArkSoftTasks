using Microsoft.EntityFrameworkCore;
using WriteService.Model;

namespace WriteService.Data
{
    public class AppDbContext:DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }
        public DbSet<Post> Posts { get; set; } = null!;
    }
    
}
