using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace CriClient
{
    public static class Dataholder
    {
        public static string loggedInUserName = "";
        public static Dictionary<string, string> userIPs = new Dictionary<string, string>(); // key username, value ip
        public static Dictionary<string, byte[]> userMasterSecrets = new Dictionary<string, byte[]>(); // key ip address, value master secret
        public static Dictionary<string, byte[]> userNonces = new Dictionary<string, byte[]>(); // key ip address, value nonce
        public static Dictionary<string, RSACryptoServiceProvider> userPublicKeys = new Dictionary<string,RSACryptoServiceProvider>(); // key ip address, value nonce
        public static Dictionary<Guid, Dictionary<string, string>> groupMemberIps = new Dictionary<Guid, Dictionary<string, string>>();

        public static RSA ClientRSA;
        
        public static RSA CA_RSA;
    }
}
