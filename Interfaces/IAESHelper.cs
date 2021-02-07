using System;
namespace DotNet_RSA.Interfaces
{
    public interface IAESHelper
    {
        string Decrypt(string value, string aesKey);
    }
}
