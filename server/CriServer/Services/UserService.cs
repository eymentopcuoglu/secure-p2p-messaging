using CriServer.IServices;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace CriServer.Services
{
    // Database access layer for users
    class UserService : IUserService
    {
        private const int USERNAME_MAX_CHARACTER_LIMIT = 16;
        private const int PASSWORD_MAX_CHARACTER_LIMIT = 16;


        private readonly CriContext _criContext;

        public UserService(IServiceProvider services)
        {
            _criContext = services.GetService<CriContext>();
        }

        public RegistryResponse RegisterUser(string username, string password)
        {
            if (!IsUserValid(username, password))
                return RegistryResponse.REGISTER_INVALID_USERNAME_OR_PASSWORD;

            if (GetUserByUsername(username) != null)
                return RegistryResponse.REGISTER_USERNAME_ALREADY_REGISTERED;

            _criContext.Add(new User()
            {
                Username = username,
                Password = password
            });
            _criContext.SaveChanges();

            return RegistryResponse.REGISTER_SUCCESSFUL;
        }

        public RegistryResponse LoginUser(string username, string password, IPAddress ipAddress)
        {
            User user = GetUserByUsername(username);

            if (user == null)
                return RegistryResponse.LOGIN_FAIL;

            if (password != user.Password)
                return RegistryResponse.LOGIN_FAIL;

            user.IpAddress = ipAddress;
            _criContext.SaveChanges();

            return RegistryResponse.LOGIN_SUCCESSFUL;
        }

        public RegistryResponse LogoutUser(IPAddress ipAddress)
        {
            User user = GetUserByIPAddress(ipAddress);

            if (user != null)
            {
                user.IpAddress = IPAddress.None;
                _criContext.SaveChanges();
            }

            return RegistryResponse.LOGOUT_SUCCESSFUL;
        }

        public RegistryResponse Search(string username)
        {
            User user = GetUserByUsername(username);

            if (user == null)
                return RegistryResponse.SEARCH_USER_NOT_FOUND;

            if (user.IpAddress.Equals(IPAddress.None))
                return RegistryResponse.SEARCH_USER_OFFLINE;

            return RegistryResponse.SEARCH_USER_ONLINE(user.IpAddress);
        }

        public User GetUserByUsername(string username)
        {
            return _criContext.Users.FirstOrDefault(u => u.Username == username);
        }

        private User GetUserByIPAddress(IPAddress ipAddress)
        {
            return _criContext.Users.FirstOrDefault(u => u.IpAddress.Equals(ipAddress));
        }

        private List<User> GetUsersByUsernames(List<string> usernames)
        {
            return _criContext.Users.Where(u => usernames.Contains(u.Username)).ToList();
        }

        private bool IsUserValid(string username, string password)
        {
            return username.Length <= USERNAME_MAX_CHARACTER_LIMIT &&
                   password.Length <= PASSWORD_MAX_CHARACTER_LIMIT;
        }
    }
}