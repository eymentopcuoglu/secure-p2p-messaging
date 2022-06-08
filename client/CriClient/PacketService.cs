using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Timers;
using Timer = System.Timers.Timer;

namespace CriClient
{
    static class PacketService
    {
        public static bool tcpPacketIncoming = false;
        public static bool isChatting = false;
        public static string chattingWithUser = "";
        public static bool canAcceptChatRequest = false;
        static Timer HbTimer;
        private static TcpListener tcpListener;
        private static bool isListeningEnabled = false;
        private static bool isTextAvailable = false;
        private static string lastTextMessage = "";

        const int USERNAME_MAX_LENGTH = 16;
        const int PASSWORD_MAX_LENGTH = 16;

        const int SERVER_TCP_PORT = 5553;
        const int SERVER_UDP_PORT = 5554;
        const string SERVER = "172.27.85.107";

        const int CLIENT_TCP_PORT = 5555;

        const int MESSAGE_MAX_LENGTH = 325;
        const int MAX_USER_COUNT = 100;


        public const string CA_PUBLIC_KEY_FILE_PATH = "ca.public.key";

        public static string SendPacket(bool isUdp, string payload, string destinationIP = SERVER, int destinationPort = SERVER_TCP_PORT)
        {
            byte[] data = Encoding.UTF8.GetBytes(payload);

            if (!isUdp)
            {
                TcpClient client = new TcpClient(destinationIP, destinationPort);
                NetworkStream stream = client.GetStream();
                stream.Write(data, 0, data.Length);

                List<byte> bytes = new List<byte>();
                int i;
                while ((i = stream.ReadByte()) != -1)
                {
                    bytes.Add((byte) i);
                }

                string dataRead = Encoding.UTF8.GetString(bytes.ToArray());
                stream.Close();
                return dataRead;
            }
            else
            {
                UdpClient udpClient = new UdpClient();
                udpClient.Send(data, data.Length, destinationIP, destinationPort);
            }

            return "";
        }

        public static void SendHeartbeat(string username)
        {
            HbTimer = new Timer() { Interval = 6000, AutoReset = true };
            HbTimer.Elapsed += (sender, e) => HeartBeat(sender, e, username);
            HbTimer.Start();
        }

        public static void KillHeartbeat()
        {
            HbTimer.Stop();
            HbTimer.Dispose();
            HbTimer = null;
        }

        private static void HeartBeat(object sender, ElapsedEventArgs e, string username)
        {
            SendPacket(true, ProtocolCode.Hello + "\n" + username, destinationPort: SERVER_UDP_PORT);
        }

        public static void StartTcpListen()
        {
            isListeningEnabled = true;
            canAcceptChatRequest = true;
            Thread tcpListenThread = new Thread(() => TcpListen());
            tcpListenThread.Start();
        }

        public static void StopTcpListen()
        {
            isListeningEnabled = false;
            canAcceptChatRequest = false;
        }

        private static void TcpListen()
        {
            tcpListener = new TcpListener(IPAddress.Any, CLIENT_TCP_PORT);
            tcpListener.Start();
            while (isListeningEnabled)
            {
                if (!tcpListener.Pending())
                {
                    Thread.Sleep(20);
                }
                else
                {
                    new Thread(() =>
                    {
                        TcpClient client = tcpListener.AcceptTcpClient();
                        tcpPacketIncoming = true;
                        NetworkStream incomingStream = client.GetStream();

                        byte[] incomingBuffer = new byte[2048];
                        incomingStream.Read(incomingBuffer, 0, incomingBuffer.Length);
                        string messageReceived = Encoding.UTF8.GetString(incomingBuffer.Select(b => b).Where(b => b != 0).ToArray());

                        string remoteAddress = client.Client.RemoteEndPoint.ToString();
                        string remoteIP = remoteAddress.Substring(0, (remoteAddress.IndexOf(':') == -1 ? remoteAddress.Length : remoteAddress.IndexOf(':')));

                        string[] parsedMessage = messageReceived.Split("\n");
                        if (ProtocolCode.Text.Equals(parsedMessage[0]))
                        {
                            isTextAvailable = true;
                            lastTextMessage = parsedMessage[2];
                        }
                        else if (ProtocolCode.Chat.Equals(parsedMessage[0]))
                        {
                            string response = RespondToChatRequest(remoteAddress);
                            byte[] data = Encoding.UTF8.GetBytes(response);
                            incomingStream.Write(data, 0, data.Length);
                        }
                        else if (ProtocolCode.GroupText.Equals(parsedMessage[0]))
                        {
                            Console.WriteLine("Incoming group message from {0}@{1}", parsedMessage[2], parsedMessage[1]);
                            Console.WriteLine(parsedMessage[3]);
                            Console.WriteLine();
                        }
                        else if (ProtocolCode.Handshake.Equals(parsedMessage[0]))
                        {
                            if (parsedMessage[1].Equals("INIT"))
                            {
                                byte[] publicKeyOfPeer = Convert.FromBase64String(parsedMessage[2]);
                                RSACryptoServiceProvider peerRSA = new RSACryptoServiceProvider();
                                peerRSA.ImportRSAPublicKey(publicKeyOfPeer, out _);
                                Dataholder.userPublicKeys[remoteIP] = peerRSA;
                                
                                int nonce = new Random().Next();
                                Dataholder.userNonces[remoteIP] = BitConverter.GetBytes(nonce);

                                string noncePacket = ProtocolCode.Handshake + "\nNONCE\n" + nonce + "\n" + Convert.ToBase64String(Dataholder.ClientRSA.ExportRSAPublicKey());
                                SendPacket(false, noncePacket, remoteIP, CLIENT_TCP_PORT);
                            }
                            else if (parsedMessage[1].Equals("NONCE"))
                            {
                                byte[] nonce = BitConverter.GetBytes(int.Parse(parsedMessage[2]));
                                byte[] publicKeyOfPeer = Convert.FromBase64String(parsedMessage[3]);

                                RSACryptoServiceProvider peerRSA = new RSACryptoServiceProvider();
                                peerRSA.ImportRSAPublicKey(publicKeyOfPeer, out _);
                                byte[] encryptedNonce = peerRSA.Encrypt(nonce, RSAEncryptionPadding.Pkcs1);

                                string encryptedNoncePacket = ProtocolCode.Handshake + "\nNONCEENC\n" + Convert.ToBase64String(encryptedNonce);
                                SendPacket(false, encryptedNoncePacket, remoteIP, CLIENT_TCP_PORT);
                                
                                Dataholder.userPublicKeys[remoteIP] = peerRSA;
                            }
                            else if (parsedMessage[1].Equals("NONCEENC"))
                            {
                                byte[] encryptedNonce = Convert.FromBase64String(parsedMessage[2]);

                                byte[] nonce = Dataholder.ClientRSA.Decrypt(encryptedNonce, RSAEncryptionPadding.Pkcs1);

                                if (nonce.SequenceEqual(Dataholder.userNonces[remoteIP]))
                                {
                                    string nonceAckPacket = ProtocolCode.Handshake + "\nNONCEACK";
                                    SendPacket(false, nonceAckPacket, remoteIP, CLIENT_TCP_PORT);
                                }
                                else
                                {
                                    string nonceInvalidPacket = ProtocolCode.Handshake + "\nINVALIDNONCE";
                                    SendPacket(false, nonceInvalidPacket, remoteIP, CLIENT_TCP_PORT);
                                }
                            }
                            else if (parsedMessage[1].Equals("NONCEACK"))
                            {
                                byte[] nonce = Dataholder.userNonces[remoteIP];
                                
                                Rfc2898DeriveBytes masterSecret = new Rfc2898DeriveBytes(nonce, nonce, 100);
                                byte[] masterSecretBytes = masterSecret.GetBytes(16);
                                byte[] encryptedMasterSecret = Dataholder.userPublicKeys[remoteIP].Encrypt(masterSecretBytes, RSAEncryptionPadding.Pkcs1);
                                string masterSecretPacket = ProtocolCode.Handshake + "\nMASTERSECRET\n" + Convert.ToBase64String(encryptedMasterSecret);
                                SendPacket(false, masterSecretPacket, remoteIP, CLIENT_TCP_PORT);

                                Dataholder.userMasterSecrets[remoteIP] = masterSecretBytes;
                            }
                            else if (parsedMessage[1].Equals("INVALIDNONCE"))
                            {
                                Console.WriteLine("Invalid nonce received from {0}", remoteIP);
                            }
                            else if (parsedMessage[1].Equals("MASTERSECRET"))
                            {
                                byte[] masterSecret = Convert.FromBase64String(parsedMessage[2]);
                                
                                Dataholder.userMasterSecrets[remoteIP] = masterSecret;
                            }

                            isTextAvailable = true;
                            lastTextMessage = parsedMessage[2];
                        }

                        incomingStream.Close();
                        tcpPacketIncoming = false;
                    }).Start();
                }
            }

            tcpListener.Stop();
            tcpListener = null;
        }

        public static void StartChat(string destination)
        {
            canAcceptChatRequest = false;
            StringBuilder outgoingStringBuffer = new StringBuilder("> ");
            string destinationIp = "";
            if (Dataholder.userIPs.ContainsKey(destination))
            {
                destinationIp = Dataholder.userIPs[destination];
            }
            else if (IPAddress.TryParse(destination, out IPAddress _))
            {
                destinationIp = destination;
            }
            else
            {
                Response response = Search(destination);
                if (response.IsSuccessful)
                {
                    destination = Dataholder.userIPs[destination];
                }
                else
                {
                    throw new Exception(response.MessageToUser);
                }
            }

            Console.Clear();
            Console.WriteLine("---------- Chat with {0} ----------", destination);
            Console.WriteLine("--------- Type :q to exit ---------");
            Console.Write("> ");
            while (true)
            {
                if (Console.KeyAvailable)
                {
                    ConsoleKeyInfo pressedKey = Console.ReadKey(true);
                    if (pressedKey.Key == ConsoleKey.Enter)
                    {
                        if (outgoingStringBuffer.Length <= 2)
                        {
                            continue;
                        }

                        Text(Dataholder.loggedInUserName, outgoingStringBuffer.Remove(0, 2).ToString(), destinationIp);
                        if (outgoingStringBuffer.ToString() == ":q")
                        {
                            break;
                        }

                        outgoingStringBuffer.Clear().Append("> ");
                        Console.Write("\n> ");
                        continue;
                    }
                    else if (pressedKey.Key == ConsoleKey.Backspace)
                    {
                        outgoingStringBuffer.Remove(outgoingStringBuffer.Length - 1, 1);
                    }
                    else
                    {
                        outgoingStringBuffer.Append(pressedKey.KeyChar);
                    }

                    int currentLine = Console.CursorTop;
                    Console.SetCursorPosition(0, currentLine);
                    Console.Write(new string(' ', Console.WindowWidth));
                    Console.SetCursorPosition(0, currentLine);
                    Console.Write(outgoingStringBuffer.ToString());
                }

                if (isTextAvailable)
                {
                    isTextAvailable = false;
                    if (lastTextMessage == ":q")
                    {
                        break;
                    }

                    int currentLine = Console.CursorTop;
                    Console.SetCursorPosition(0, currentLine);
                    Console.Write(new string(' ', Console.WindowWidth));
                    Console.SetCursorPosition(0, currentLine);
                    Console.WriteLine(lastTextMessage);
                    Console.Write(outgoingStringBuffer.ToString());
                }
            }

            Console.Clear();
            canAcceptChatRequest = true;
            isChatting = false;
            isTextAvailable = false;
        }

        private static string RespondToChatRequest(string fromIp)
        {
            // TODO decouple this as this should be a UI method
            if (!canAcceptChatRequest)
            {
                return ProtocolCode.Chat + "\nBUSY";
            }

            char userOption = '\0';
            while (!(userOption == 'Y' || userOption == 'N'))
            {
                Console.WriteLine("\nIncoming chat request from {0}", fromIp);
                if (Dataholder.userIPs.ContainsValue(fromIp))
                {
                    Console.WriteLine("This IP was last seen online as user {0}", Dataholder.userIPs.FirstOrDefault((userIp) => userIp.Value == fromIp).Key);
                }

                Console.Write("Would you like to accept the request? (Enter, and then Y or N)");
                userOption = char.ToUpper(Console.ReadKey().KeyChar);
                Console.WriteLine();
            }

            if (userOption == 'Y')
            {
                isChatting = true;
                chattingWithUser = fromIp.Substring(0, (fromIp.IndexOf(':') == -1 ? fromIp.Length : fromIp.IndexOf(':')));
                return ProtocolCode.Chat + "\nOK";
            }
            else
            {
                return ProtocolCode.Chat + "\nREJECT";
            }
        }

        public static string ReceivePacket()
        {
            TcpListener server = new TcpListener(IPAddress.Any, CLIENT_TCP_PORT);
            server.Start();
            List<byte> bytes = new List<byte>();
            string data = null;
            TcpClient client = server.AcceptTcpClient();
            NetworkStream stream = client.GetStream();

            int i;
            while ((i = stream.ReadByte()) != -1)
            {
                bytes.Add((byte) i);
            }

            data = Encoding.UTF8.GetString(bytes.ToArray());
            client.Close();
            server.Stop();
            return data;
        }


        public static Response Register(string username, string password)
        {
            if (username.Length <= USERNAME_MAX_LENGTH && password.Length <= PASSWORD_MAX_LENGTH)
            {
                string packet = ProtocolCode.Register + "\n" + username + "\n" + password + "\n" + Convert.ToBase64String(Dataholder.ClientRSA.ExportRSAPublicKey());
                string answer = SendPacket(false, packet);
                string[] tokenizedanswer;
                int counter = 0;
                do
                {
                    tokenizedanswer = answer.Split("\n");
                    counter++;
                } while (!ProtocolCode.Register.Equals(tokenizedanswer[0]) && counter < 2);

                if (tokenizedanswer[1] == "ALREADY_EXISTS")
                {
                    return new Response() { IsSuccessful = false, MessageToUser = "This user already exists." };
                }

                if (tokenizedanswer[1] == "OK")
                {
                    string base64EncodedCertificate = tokenizedanswer[2];

                    bool isValid = Dataholder.CA_RSA.VerifyData(Dataholder.ClientRSA.ExportRSAPublicKey(),
                                                                Convert.FromBase64String(base64EncodedCertificate),
                                                                HashAlgorithmName.SHA256,
                                                                RSASignaturePadding.Pkcs1);

                    if (isValid)
                        return new Response() { IsSuccessful = true, MessageToUser = "Certificate is valid!!! Registered Successfully!" };
                    else
                        return new Response() { IsSuccessful = false, MessageToUser = "Certificate can not be verified" };
                }

                return new Response() { IsSuccessful = false, MessageToUser = "Unknown Error" };
            }
            else
            {
                throw new Exception("username or password char limit exceeded");
            }

            return null;
        }

        public static Response Login(string username, string password)
        {
            if (username.Length <= USERNAME_MAX_LENGTH && password.Length <= PASSWORD_MAX_LENGTH)
            {
                string packet = ProtocolCode.Login + "\n" + username + "\n" + password;
                string answer = SendPacket(false, packet);
                string[] tokenizedanswer;
                int counter = 0;
                do
                {
                    tokenizedanswer = answer.Split("\n");
                    counter++;
                } while (!ProtocolCode.Login.Equals(tokenizedanswer[0]) && counter < 2);

                if (tokenizedanswer[1] == "OK")
                {
                    SendHeartbeat(username);
                    return new Response { IsSuccessful = true, MessageToUser = "Login successful. " };
                }

                if (tokenizedanswer[1] == "FAIL")
                {
                    return new Response { IsSuccessful = false, MessageToUser = "Cannot login. " };
                }

                return new Response() { IsSuccessful = false, MessageToUser = "Unknown Error" };
            }
            else
            {
                throw new Exception("username or password char limit exceeded");
            }
        }

        public static Response Logout(string username)
        {
            string packet = ProtocolCode.Logout.ToString() + "\n" + username;
            string answer = SendPacket(false, packet);
            string[] tokenizedanswer;
            tokenizedanswer = answer.Split("\n");
            if (tokenizedanswer[1] == "OK")
            {
                KillHeartbeat();
                return new Response { IsSuccessful = true, MessageToUser = "Logged out. " };
            }

            return new Response() { IsSuccessful = false, MessageToUser = "Unknown Error" };
        }

        public static Response Search(string username)
        {
            if (username.Length <= USERNAME_MAX_LENGTH)
            {
                string packet = ProtocolCode.Search + "\n" + username;
                string answer = SendPacket(false, packet);
                string[] tokenizedanswer;
                int counter = 0;
                do
                {
                    tokenizedanswer = answer.Split("\n");
                    counter++;
                } while (!ProtocolCode.Search.Equals(tokenizedanswer[0]) && counter < 2);

                if (tokenizedanswer[1] == "OFFLINE")
                {
                    return new Response { IsSuccessful = false, MessageToUser = "User is offline. " };
                }

                if (tokenizedanswer[1] == "NOT_FOUND")
                {
                    return new Response { IsSuccessful = false, MessageToUser = "User not found. " };
                }

                if (tokenizedanswer[1] == "OK")
                {
                    if (Dataholder.userIPs.ContainsKey(username))
                    {
                        Dataholder.userIPs[username] = tokenizedanswer[2];
                    }
                    else
                    {
                        Dataholder.userIPs.Add(username, tokenizedanswer[2]);
                    }

                    return new Response { IsSuccessful = true, MessageToUser = "User is online. " };
                }

                return new Response() { IsSuccessful = false, MessageToUser = "Unknown Error" };
            }
            else
            {
                throw new Exception("username char limit exceeded");
            }
        }

        public static Response Chat(string username)
        {
            if (username.Length > USERNAME_MAX_LENGTH)
            {
                throw new Exception("Username char limit exceeded");
            }

            Response searchanswer = Search(username);
            if (searchanswer.IsSuccessful)
            {
                string destIp = Dataholder.userIPs[username];


                string packet = ProtocolCode.Chat + "\n" + username;
                Console.WriteLine("Sending P2P chat request to: {0}", destIp);
                string answer = SendPacket(false, packet, destIp, CLIENT_TCP_PORT);
                string[] tokenizedanswer = answer.Split('\n');
                if (tokenizedanswer[1] == "BUSY")
                {
                    return new Response() { IsSuccessful = false, MessageToUser = "This user is currently busy." };
                }

                if (tokenizedanswer[1] == "REJECT")
                {
                    return new Response() { IsSuccessful = false, MessageToUser = "The user has rejected your chat request." };
                }

                if (tokenizedanswer[1] == "OK")
                {
                    string handshakePacket = ProtocolCode.Handshake + "\nINIT\n" + Convert.ToBase64String(Dataholder.ClientRSA.ExportRSAPublicKey());
                    Console.WriteLine("Sending handshake request to: {0}", destIp);
                    SendPacket(false, handshakePacket, destIp, CLIENT_TCP_PORT);
                    
                    return new Response() { IsSuccessful = true, MessageToUser = "Handshake request successfully sent!" };
                }

                return new Response() { IsSuccessful = false, MessageToUser = "Unknown error." };
            }
            else
            {
                return searchanswer;
            }
        }

        public static void Text(string username, string message, string destinationIp)
        {
            if (username.Length <= USERNAME_MAX_LENGTH && message.Length <= MESSAGE_MAX_LENGTH)
            {
                string packet = ProtocolCode.Text + "\n" + username + "\n" + message;
                SendPacket(false, packet, destinationIp, CLIENT_TCP_PORT);
            }
            else
            {
                throw new Exception("username or message char limit exceeded");
            }
        }

        public static Response GroupCreate(List<string> usernames)
        {
            if (usernames.Count <= MAX_USER_COUNT)
            {
                string packet = ProtocolCode.GroupCreate + "\n" + string.Join("\n", usernames);
                string answer = SendPacket(false, packet);
                string[] tokenizedanswer = answer.Split("\n");
                if (tokenizedanswer[1] == "NOT_FOUND")
                {
                    List<string> listAnswer = new List<string>(tokenizedanswer);
                    return new Response { IsSuccessful = false, MessageToUser = "Following users are not found: " + string.Join("\n", tokenizedanswer.TakeLast(tokenizedanswer.Length - 2)) };
                }

                if (tokenizedanswer[1] == "OK")
                {
                    return new Response { IsSuccessful = true, MessageToUser = "Group successfully created. " };
                }

                return new Response() { IsSuccessful = false, MessageToUser = "Unknown Error" };
            }
            else
            {
                throw new Exception("user count limit exceeded");
            }
        }

        public static Response GroupSearch(Guid gid)
        {
            string packet = ProtocolCode.GroupSearch + "\n" + gid;
            string answer = SendPacket(false, packet);
            string[] tokenizedanswer = answer.Split("\n");
            if (tokenizedanswer[1] == "NOT_FOUND")
            {
                return new Response { IsSuccessful = false, MessageToUser = "Group with the given ID doesn't exist." };
            }

            if (tokenizedanswer[1] == "OK")
            {
                if (!Dataholder.groupMemberIps.ContainsKey(gid))
                {
                    Dataholder.groupMemberIps.Add(gid, new Dictionary<string, string>());
                }

                Dictionary<string, string> groupMembers = Dataholder.groupMemberIps[gid];
                for (int i = 2; i < tokenizedanswer.Length; i += 2)
                {
                    if (tokenizedanswer[i] == "255.255.255.255")
                    {
                        continue;
                    }

                    if (!groupMembers.ContainsKey(tokenizedanswer[i + 1]))
                    {
                        groupMembers.Add(tokenizedanswer[i + 1], tokenizedanswer[i]);
                    }
                    else
                    {
                        groupMembers[tokenizedanswer[i + 1]] = tokenizedanswer[i];
                    }
                }

                return new Response { IsSuccessful = true, MessageToUser = string.Join("\n", tokenizedanswer.TakeLast(tokenizedanswer.Length - 2)) };
            }

            return new Response() { IsSuccessful = false, MessageToUser = "Unknown Error" };
        }

        public static void GroupText(Guid gid, string username, string message)
        {
            if (!Dataholder.groupMemberIps.ContainsKey(gid))
            {
                throw new Exception("Group does not exist.");
            }

            if (username.Length <= USERNAME_MAX_LENGTH && message.Length <= MESSAGE_MAX_LENGTH)
            {
                Dictionary<string, string> userIps = Dataholder.groupMemberIps[gid];
                string packet = ProtocolCode.GroupText + "\n" + gid + "\n" + username + "\n" + message;
                foreach (string ip in userIps.Values)
                {
                    SendPacket(false, packet, ip, CLIENT_TCP_PORT);
                }
            }
            else
            {
                throw new Exception("username or message char limit exceeded");
            }
        }

        public static void SetCAPublicKey()
        {
            string packet = ProtocolCode.CAPublicKey + "";
            string answer = SendPacket(false, packet);
            string[] tokenizedanswer;
            int counter = 0;
            do
            {
                tokenizedanswer = answer.Split("\n");
                counter++;
            } while (!ProtocolCode.CAPublicKey.Equals(tokenizedanswer[0]) && counter < 2);

            string base64EncodedPublicKey = tokenizedanswer[1];

            File.WriteAllText(CA_PUBLIC_KEY_FILE_PATH, base64EncodedPublicKey);

            byte[] publicKeyBytes = Convert.FromBase64String(base64EncodedPublicKey);

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportRSAPublicKey(publicKeyBytes, out _);

            Dataholder.CA_RSA = rsa;
        }
    }
}