using System.Net;

namespace CriServer.Dtos
{
    public class UserIpDto
    {
        public IPAddress IpAddress { get; set; }
        public string Username { get; set; }

        public override string ToString()
        {
            return IpAddress + "\n" + Username;
        }
    }
}