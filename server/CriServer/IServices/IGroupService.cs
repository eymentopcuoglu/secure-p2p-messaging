using System;
using System.Collections.Generic;

namespace CriServer.IServices
{
    interface IGroupService
    {
        RegistryResponse CreateGroup(List<string> usernames);
        RegistryResponse SearchGroup(Guid groupId);
    }
}
