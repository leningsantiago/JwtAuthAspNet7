using System.ComponentModel.DataAnnotations;

namespace JwtAuthAspNet7.Models.Dto
{
    public class RegisterDto
    {
        [Required(ErrorMessage = "UserName is Required")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Email is Required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Email is Required")]
        public string Password { get; set; }
    }
}
