using CriServer.Dtos;
using System.Collections.Generic;
using System.Net;

namespace CriServer
{
    // Represents the response returned from the registry
    public class RegistryResponse
    {
        private string Value { get; }

        private RegistryResponse(string value)
        {
            Value = value;
        }

        public static RegistryResponse REGISTER_SUCCESSFUL => new(ProtocolCode.Register + "\nOK");

        public static RegistryResponse REGISTER_INVALID_USERNAME_OR_PASSWORD => new(ProtocolCode.Register + "\nFAIL");

        public static RegistryResponse REGISTER_USERNAME_ALREADY_REGISTERED =>
            new(ProtocolCode.Register + "\nALREADY_EXISTS");

        public static RegistryResponse LOGIN_SUCCESSFUL => new(ProtocolCode.Login + "\nOK");
        public static RegistryResponse LOGIN_FAIL => new(ProtocolCode.Login + "\nFAIL");

        public static RegistryResponse LOGOUT_SUCCESSFUL => new(ProtocolCode.Logout + "\nOK");

        public static RegistryResponse SEARCH_USER_ONLINE(IPAddress ipAddress) =>
            new(ProtocolCode.Search + "\nOK\n" + ipAddress);

        public static RegistryResponse SEARCH_USER_OFFLINE => new(ProtocolCode.Search + "\nOFFLINE");
        public static RegistryResponse SEARCH_USER_NOT_FOUND => new(ProtocolCode.Search + "\nNOT_FOUND");

        public static RegistryResponse GROUP_CREATE_SUCCESSFUL => new(ProtocolCode.GroupCreate + "\nOK");
        public static RegistryResponse GROUP_CREATE_USER_NOT_FOUND(List<string> usernames) =>
            new(ProtocolCode.GroupCreate + "\nNOT_FOUND\n" + string.Join("\n", usernames));
        public static RegistryResponse GROUP_CREATE_FAIL => new(ProtocolCode.GroupCreate + "\nFAIL");

        public static RegistryResponse GROUP_SEARCH_SUCCESSFUL(List<UserIpDto> userIpDtos) => new(ProtocolCode.GroupSearch + "\nOK\n"+ string.Join("\n", userIpDtos));
        public static RegistryResponse GROUP_SEARCH_NOT_FOUND => new(ProtocolCode.GroupSearch + "\nNOT_FOUND");

        public override string ToString()
        {
            return Value;
        }

        public override bool Equals(object obj)
        {
            if (obj is string)
                return Value == obj.ToString();
            if (obj is not RegistryResponse registryResponse)
                return false;

            return Value == registryResponse.Value;
        }
    }
}