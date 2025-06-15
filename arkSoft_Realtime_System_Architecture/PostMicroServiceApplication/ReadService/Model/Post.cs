using System.ComponentModel.DataAnnotations;

namespace ReadService.Model
{
    public class Post
    {


        [Key]
        public Guid PostId { get; set; } = Guid.NewGuid();

        [Required]
        public string PostContent { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    }
}
