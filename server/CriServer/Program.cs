using CriServer.IServices;
using CriServer.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using System;
using System.IO;
using System.Security.Cryptography;

namespace CriServer
{
    class Program
    {
        static void Main(string[] args)
        {
            IConfiguration configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .Build();
            
            string connectionStringOption = "PostgresDefault";
            if (args.Length == 1 && args[0] == "--is-standalone")
            {
                connectionStringOption = "PostgresStandalone";
            }

            IHost host = Host.CreateDefaultBuilder(args)
                .ConfigureServices((_, services) =>
                    services
                        .AddDbContext<CriContext>(options =>
                            options.UseNpgsql(configuration.GetConnectionString(connectionStringOption)))
                        .AddScoped<IUserService, UserService>()
                        .AddScoped<IGroupService, GroupService>()
                ).Build();
            
            CriContext dbContext = host.Services.GetService<CriContext>();
            dbContext?.Database.EnsureCreated();
            //dbContext?.Database.Migrate();

            Log.Logger = new LoggerConfiguration()
                .WriteTo.Console()
                .WriteTo.File("./log/criserver.log", rollingInterval: RollingInterval.Day,
                    flushToDiskInterval: TimeSpan.FromSeconds(1))
                .CreateLogger();
            Log.Logger.Information("Starting registry server listeners."); // Do not delete!
            
            RegistryServer registryServer = new RegistryServer(host.Services.GetService<IUserService>(), host.Services.GetService<IGroupService>());
            registryServer.Start();

            Log.CloseAndFlush();
        }
    }
}