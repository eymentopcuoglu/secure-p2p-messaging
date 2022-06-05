using System;
using System.Collections.Generic;

namespace CriClient
{
    public static class Dataholder
    {
        public static string loggedInUserName = "";
        public static Dictionary<string, string> userIPs = new Dictionary<string, string>();
        public static Dictionary<Guid, Dictionary<string, string>> groupMemberIps = new Dictionary<Guid, Dictionary<string, string>>();
    }
}
