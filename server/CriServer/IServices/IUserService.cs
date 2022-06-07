using System.Net;

namespace CriServer.IServices
{
    interface IUserService
    {
        RegistryResponse RegisterUser(string username, string password, string base64EncodedCertificate);
        RegistryResponse LoginUser(string username, string password, IPAddress ipAddress);
        RegistryResponse LogoutUser(IPAddress ipAddress);
        RegistryResponse Search(string username);
        User GetUserByUsername(string username);
    }
}