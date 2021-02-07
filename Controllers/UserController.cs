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
        private readonly IAESHelper AESHelper;
        public UserController(IRSAHelper rsaHelper, IAESHelper aesHelper)
        {
            RSAHelper = rsaHelper;
            AESHelper = aesHelper;
        }

        [HttpPost]
        [Route("basic-login")]
        public ActionResult<string> LoginBasic([FromBody] RSAUser user)
        {
            var result = Newtonsoft.Json.JsonConvert.SerializeObject(user);
            return Ok(result);
        }

        [HttpPost]
        [Route("rsa-login")]
        public ActionResult<string> LoginRSA([FromBody] RSAUser user)
        {
            var clearUser = new RSAUser();
            clearUser.UserName = RSAHelper.Decrypt(user.UserName);
            clearUser.Password = RSAHelper.Decrypt(user.Password);

            var result = Newtonsoft.Json.JsonConvert.SerializeObject(clearUser);
            return Ok(result);
        }


        [HttpPost]
        [Route("rsa-advanced-login")]
        public ActionResult<string> LoginRSAAdvanced([FromBody] RSAUserData userData)
        {
            var userJson = RSAHelper.Decrypt(userData.Data);
            var cleanUser = Newtonsoft.Json.JsonConvert.DeserializeObject<RSAUser>(userJson);
            return Ok(cleanUser);
        }

        [HttpPost]
        [Route("aes-login")]
        public ActionResult<string> LoginAES([FromBody] AESUser user)
        {
            var clearUser = new AESUser();
            clearUser.UserName = AESHelper.Decrypt(user.UserName, user.AESKey);
            clearUser.Password = AESHelper.Decrypt(user.Password, user.AESKey);
            clearUser.AESKey = "";

            var result = Newtonsoft.Json.JsonConvert.SerializeObject(clearUser);
            return Ok(result);
        }


        [HttpPost]
        [Route("aes-advanced-login")]
        public ActionResult<string> LoginAESAdvanced([FromBody] AESUserData userData)
        {
            var userJson = AESHelper.Decrypt(userData.Data, userData.AESKey);
            var cleanUser = Newtonsoft.Json.JsonConvert.DeserializeObject<AESUser>(userJson);
            return Ok(cleanUser);
        }

        [HttpPost]
        [Route("aes-rsa-login")]
        public ActionResult<string> LoginAESRSA([FromBody] AESUser user)
        {
            var keyValue = RSAHelper.Decrypt(user.AESKey);
            var clearUser = new AESUser();
            clearUser.UserName = AESHelper.Decrypt(user.UserName, keyValue);
            clearUser.Password = AESHelper.Decrypt(user.Password, keyValue);
            clearUser.AESKey = "";

            var result = Newtonsoft.Json.JsonConvert.SerializeObject(clearUser);
            return Ok(result);
        }


        [HttpPost]
        [Route("aes-rsa-advanced-login")]
        public ActionResult<string> LoginAESAdvancedRSA([FromBody] AESUserData userData)
        {
            var keyValue = RSAHelper.Decrypt(userData.AESKey);
            var userJson = AESHelper.Decrypt(userData.Data, keyValue);
            var cleanUser = Newtonsoft.Json.JsonConvert.DeserializeObject<AESUser>(userJson);
            return Ok(cleanUser);
        }
    }
}