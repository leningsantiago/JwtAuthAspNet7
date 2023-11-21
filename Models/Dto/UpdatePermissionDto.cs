using System.ComponentModel.DataAnnotations;

namespace JwtAuthAspNet7.Models.Dto
{
    public class UpdatePermissionDto
    {
        [Required(ErrorMessage = "UserName is Required")]
        public string UserName { get; set; }

    }
}
