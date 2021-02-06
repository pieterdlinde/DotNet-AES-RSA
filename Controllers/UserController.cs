using DotNet_RSA.Interfaces;
using DotNet_RSA.Models;
using Microsoft.AspNetCore.Mvc;

namespace DotNet_RSA.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly IRSAHelper RSAHelper;
        public UserController(IRSAHelper rsaHelper) => RSAHelper = rsaHelper;

        [HttpPost]
        [Route("basic-login")]
        public ActionResult<string> LoginBasic([FromBody] User user)
        {
            var result = Newtonsoft.Json.JsonConvert.SerializeObject(user);
            return Ok(result);
        }

        [HttpPost]
        [Route("rsa-login")]
        public ActionResult<string> LoginRSA([FromBody] User user)
        {
            var clearUser = new User();
            clearUser.UserName = RSAHelper.Decrypt(user.UserName);
            clearUser.Password = RSAHelper.Decrypt(user.Password);

            var result = Newtonsoft.Json.JsonConvert.SerializeObject(clearUser);
            return Ok(result);
        }


        [HttpPost]
        [Route("rsa-advanced-login")]
        public ActionResult<string> LoginRSAadvanced([FromBody] UserData userData)
        {
            var userJson = RSAHelper.Decrypt(userData.Data);
            var cleanUser = Newtonsoft.Json.JsonConvert.DeserializeObject<User>(userJson);
            return Ok(cleanUser);
        }
    }
}