using CriServer.Dtos;
using CriServer.IServices;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CriServer.Services
{
    // Database access layer for groups
    class GroupService : IGroupService
    {
        private const int MAX_USER_COUNT = 100;

        private readonly CriContext _criContext;
        private readonly IUserService _userService;

        public GroupService(IServiceProvider services)
        {
            _criContext = services.GetService<CriContext>();
            _userService = services.GetService<IUserService>();
        }

        public RegistryResponse CreateGroup(List<string> usernames)
        {
            if (usernames.Count > MAX_USER_COUNT)
                return RegistryResponse.GROUP_CREATE_FAIL;

            Group newGroup = new Group();
            newGroup.Users = new List<User>();
            List<string> usersNotFound = new List<string>();
            foreach (string username in usernames)
            {
                User user = _userService.GetUserByUsername(username);

                if (user == null)
                    usersNotFound.Add(username);
                else
                    newGroup.Users.Add(user);
            }

            if (usersNotFound.Count != 0)
                return RegistryResponse.GROUP_CREATE_USER_NOT_FOUND(usersNotFound);

            _criContext.Add(newGroup);
            _criContext.SaveChanges();

            return RegistryResponse.GROUP_CREATE_SUCCESSFUL;
        }

        public RegistryResponse SearchGroup(Guid groupId)
        {
            Group group = GetGroupByGroupId(groupId);

            if (group == null)
                return RegistryResponse.GROUP_SEARCH_NOT_FOUND;

            return RegistryResponse.GROUP_SEARCH_SUCCESSFUL(group.Users.Select(user => new UserIpDto()
            {
                Username = user.Username,
                IpAddress = user.IpAddress
            }).ToList());
        }

        private Group GetGroupByGroupId(Guid groupId)
        {
            return _criContext.Groups
                .Include(g => g.Users)
                .FirstOrDefault(g => g.GroupId == groupId);
        }
    }
}