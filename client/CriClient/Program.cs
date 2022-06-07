using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;

namespace CriClient
{
    class Program
    {
        private const string PUBLIC_KEY_FILE_PATH = "public.key";
        private const string PRIVATE_KEY_FILE_PATH = "private.key";

        private static string LoggedinUsername { get; set; }
        static bool packetsent = false;

        static void Main(string[] args)
        {
            SetRSAKeyPair();

            while (true)
            {
                Console.WriteLine("1.Register\n2.Login");
                string menuopt = Console.ReadLine();
                menuopt = menuopt.ToLower();
                Console.WriteLine("Type username of max. 16 characters");
                string uname = Console.ReadLine();
                Console.WriteLine("Type password of max. 16 characters");
                string pword = Console.ReadLine();


                if (menuopt == "1" || menuopt == "register")
                {
                    Response response = PacketService.Register(uname, pword);
                    Console.WriteLine(response.MessageToUser);
                    packetsent = true;
                }
                else if (menuopt == "2" || menuopt == "login")
                {
                    Response response = PacketService.Login(uname, pword);
                    if (response.IsSuccessful == true)
                    {
                        LoggedinUsername = uname;
                        Dataholder.loggedInUserName = uname;
                        afterLogin();
                        continue;
                    }
                    else
                    {
                        Console.WriteLine(response.MessageToUser);
                        packetsent = true;
                    }
                }
                else
                {
                    Environment.Exit(0);
                }
            }
        }

        public static void afterLogin()
        {
            PacketService.StartTcpListen();
            while (true)
            {
                if (PacketService.tcpPacketIncoming)
                {
                    Thread.Sleep(20);
                    continue;
                }

                if (PacketService.isChatting)
                {
                    PacketService.StartChat(PacketService.chattingWithUser);
                }

                Console.WriteLine("1.Search\n2.Chat\n3.Create Group\n4.Search Group\n5.Text Group\n6.Logout");
                string chooseaction = Console.ReadLine();
                //chooseaction = chooseaction.ToLower();

                if (chooseaction == "1")
                {
                    Console.WriteLine("Please provide the username you would like to search ");
                    string user = Console.ReadLine();
                    Response response = PacketService.Search(user);
                    Console.WriteLine(response.MessageToUser);
                }
                else if (chooseaction == "2")
                {
                    Console.WriteLine("Please provide the username you would like to chat ");
                    string user = Console.ReadLine();
                    Response response = PacketService.Chat(user);
                    if (response.IsSuccessful)
                    {
                        PacketService.StartChat(user);
                        continue;
                    }
                    else
                    {
                        Console.WriteLine(response.MessageToUser);
                    }
                }
                else if (chooseaction == "3")
                {
                    Console.WriteLine("Please provide the users you would like to add to the group (Max. 100 users)");
                    List<string> users = new List<string>();
                    string userinput = Console.ReadLine();
                    while (!string.IsNullOrWhiteSpace(userinput))
                    {
                        users.Add(userinput);
                        userinput = Console.ReadLine();
                    }

                    Response response = PacketService.GroupCreate(users);
                    Console.WriteLine(response.MessageToUser);
                }
                else if (chooseaction == "4")
                {
                    Console.WriteLine("Please provide the Group ID og the group you would like to search");
                    Guid GrID = Guid.Parse(Console.ReadLine());
                    Response response = PacketService.GroupSearch(GrID);
                    Console.WriteLine(response.MessageToUser);
                }
                else if (chooseaction == "5")
                {
                    Console.WriteLine("Please provide the Group ID og the group you would like to text");
                    Guid GrID = Guid.Parse(Console.ReadLine());
                    Console.WriteLine("Please provide the text you would like to send");
                    string message = Console.ReadLine();
                    PacketService.GroupText(GrID, LoggedinUsername, message);
                }
                else if (chooseaction == "6")
                {
                    Response Response = PacketService.Logout(LoggedinUsername);
                    Console.WriteLine(Response.MessageToUser);
                    LoggedinUsername = "";
                    Dataholder.loggedInUserName = "";
                    PacketService.StopTcpListen();
                    return;
                }
            }
        }

        private static void SetRSAKeyPair()
        {
            if (!File.Exists(PUBLIC_KEY_FILE_PATH) || !File.Exists(PRIVATE_KEY_FILE_PATH))
            {
                RSA rsa = RSA.Create();

                string publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                string privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

                File.WriteAllText(PUBLIC_KEY_FILE_PATH, publicKey);
                File.WriteAllText(PRIVATE_KEY_FILE_PATH, privateKey);

                Dataholder.RSA = rsa;
                Dataholder.Base64EncodedPrivateKey = publicKey;
                Dataholder.Base64EncodedPublicKey = privateKey;
            }
            else
            {
                string publicKey = File.ReadAllText(PUBLIC_KEY_FILE_PATH);
                string privateKey = File.ReadAllText(PRIVATE_KEY_FILE_PATH);

                byte[] privateKeyBytes = Convert.FromBase64String(privateKey);
                byte[] publicKeyBytes = Convert.FromBase64String(publicKey);

                RSA rsa = RSA.Create();
                rsa.ImportRSAPrivateKey(privateKeyBytes, out _);
                rsa.ImportRSAPublicKey(publicKeyBytes, out _);
                
                Dataholder.RSA = rsa;
                Dataholder.Base64EncodedPrivateKey = publicKey;
                Dataholder.Base64EncodedPublicKey = privateKey;
            }
        }
    }
}