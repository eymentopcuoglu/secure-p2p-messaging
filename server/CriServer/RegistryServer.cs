using CriServer.IServices;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace CriServer
{
    class RegistryServer
    {
        private readonly IUserService _userService;
        private readonly ConcurrentDictionary<IPAddress, DateTime> _lastHeartBeats;
        private readonly IGroupService _groupService;

        private TcpListener tcpListener;
        private UdpClient udpListener;

        private const int TCP_PORT = 5555;
        private const int UDP_PORT = 5556;
        private const int ACTIVITY_TIMEOUT = 20;

        public RegistryServer(IUserService userService, IGroupService groupService)
        {
            _userService = userService;
            _groupService = groupService;
            _lastHeartBeats = new ConcurrentDictionary<IPAddress, DateTime>();
        }

        public void Start()
        {
            Thread tcpThread = new Thread(() => TcpListen(Log.Logger));
            Thread udpThread = new Thread(() => UdpListen(Log.Logger));
            Thread statusUpdaterThread = new Thread(() => UpdateStatusOfUsers(Log.Logger));
            tcpThread.Start();
            udpThread.Start();
            statusUpdaterThread.Start();
        }

        private void TcpListen(ILogger logger)
        {
            logger.Information("TcpListen() thread started");
            tcpListener = new TcpListener(IPAddress.Any, TCP_PORT);
            tcpListener.Start();
            while (true)
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
                        NetworkStream incomingStream = client.GetStream();

                        byte[] incomingBuffer = new byte[256];
                        incomingStream.Read(incomingBuffer, 0, incomingBuffer.Length);

                        logger.Information("Received TCP connection from {IP} Sleeping...",
                            client.Client.RemoteEndPoint);
                        string messageReceived =
                            Encoding.UTF8.GetString(incomingBuffer.Select(b => b).Where(b => b != 0).ToArray());
                        logger.Information("Received TCP message from {IP}:\n{Message}", client.Client.RemoteEndPoint,
                            messageReceived);

                        string[] parsedMessage = messageReceived.Split("\n");
                        ProtocolCode method = new ProtocolCode(parsedMessage[0]);
                        string[] payload = parsedMessage.Skip(1).ToArray();
                        IPAddress ipAddress = ((IPEndPoint)client.Client.RemoteEndPoint)?.Address;

                        RegistryResponse registryResponse = null;
                        if (ProtocolCode.Register.Equals(method))
                            registryResponse = Register(payload);
                        else if (ProtocolCode.Login.Equals(method))
                            registryResponse = Login(payload, ipAddress);
                        else if (ProtocolCode.Logout.Equals(method))
                            registryResponse = Logout(ipAddress);
                        else if (ProtocolCode.Search.Equals(method))
                            registryResponse = Search(payload);
                        else if (ProtocolCode.GroupCreate.Equals(method))
                            registryResponse = GroupCreate(payload);
                        else if (ProtocolCode.GroupSearch.Equals(method))
                            registryResponse = GroupSearch(payload);

                        byte[] data = Encoding.UTF8.GetBytes(registryResponse.ToString());
                        incomingStream.Write(data, 0, data.Length);

                        logger.Information("Sent TCP respone to {IP}:\n{Message}", client.Client.RemoteEndPoint,
                            registryResponse);
                        incomingStream.Close();
                    }).Start();
                }
            }
        }

        private void UdpListen(ILogger logger)
        {
            Console.WriteLine("Console says: UdpListen() thread started.");
            logger.Information("UdpListen() thread started");
            udpListener = new UdpClient(UDP_PORT);
            while (true)
            {
                IPEndPoint remoteEndPoint = null;
                byte[] incomingData = udpListener.Receive(ref remoteEndPoint);
                string payload = Encoding.UTF8.GetString(incomingData);
                List<string> tokenizedPayload = payload.Split('\n').ToList();
                if (!ProtocolCode.Hello.Equals(tokenizedPayload[0]))
                    break;
                logger.Information("Received UDP message from {IP}:\n{Message}", remoteEndPoint, tokenizedPayload);
                _lastHeartBeats[remoteEndPoint.Address] = DateTime.Now;
            }
        }

        private void UpdateStatusOfUsers(ILogger logger)
        {
            Console.WriteLine("Console says: UpdateStatusOfUsers() thread started.");
            logger.Information("UpdateStatusOfUsers() thread started");
            while (true)
            {
                List<IPAddress> ipAddressesToRemove = new List<IPAddress>();
                foreach (KeyValuePair<IPAddress, DateTime> entry in _lastHeartBeats)
                {
                    double timeElapsedInSeconds = (DateTime.Now - entry.Value).TotalSeconds;

                    if (timeElapsedInSeconds > ACTIVITY_TIMEOUT)
                    {
                        logger.Information("Logging out the user with IP Address:{IP}", entry.Key);
                        Console.WriteLine("Console says: Logging out the user with IP Address: " + entry.Key);

                        RegistryResponse response = _userService.LogoutUser(entry.Key);
                        if (RegistryResponse.LOGOUT_SUCCESSFUL.Equals(response))
                            ipAddressesToRemove.Add(entry.Key);
                    }
                }

                ipAddressesToRemove.ForEach(address => _lastHeartBeats.Remove(address, out _));
                Thread.Sleep(1000);
            }
        }

        private RegistryResponse Register(string[] payload)
        {
            return _userService.RegisterUser(payload[0], payload[1]);
        }

        private RegistryResponse Login(string[] payload, IPAddress ipAddress)
        {
            RegistryResponse response = _userService.LoginUser(payload[0], payload[1], ipAddress);

            if (RegistryResponse.LOGIN_SUCCESSFUL.Equals(response))
                _lastHeartBeats[ipAddress] = DateTime.Now;

            return response;
        }

        private RegistryResponse Logout(IPAddress ipAddress)
        {
            RegistryResponse response = _userService.LogoutUser(ipAddress);

            if (RegistryResponse.LOGOUT_SUCCESSFUL.Equals(response))
                _lastHeartBeats.Remove(ipAddress, out _);

            return response;
        }

        private RegistryResponse Search(string[] payload)
        {
            return _userService.Search(payload[0]);
        }

        private RegistryResponse GroupCreate(string[] payload)
        {
            return _groupService.CreateGroup(new List<string>(payload));
        }

        private RegistryResponse GroupSearch(string[] payload)
        {
            return _groupService.SearchGroup(new Guid(payload[0]));
        }

        public void Stop()
        {
            tcpListener.Stop();
            udpListener.Close();
            udpListener.Dispose();
        }
    }
}