using System.ComponentModel.DataAnnotations;

namespace JwtAuthAspNet7.Models.Dto
{
    public class LoginDto
    {
        [Required(ErrorMessage = "UserName is Required")]
        public string UserName { get; set; }


        [Required(ErrorMessage = "Password is Required")]
        public string Password { get; set; }
    }
}
