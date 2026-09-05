using System.Net;
using System.Net.Sockets;
using d0x2a.EmbeddedSsh.Auth;
using d0x2a.EmbeddedSsh.Protocol.Messages;
using d0x2a.EmbeddedSsh.Transport;

namespace d0x2a.EmbeddedSsh.Tests.Auth;

/// <summary>
/// Regression tests for AuthLayer's handling of non-userauth messages
/// (SSH_MSG_IGNORE / SSH_MSG_DEBUG / SSH_MSG_UNIMPLEMENTED) received during
/// authentication. RFC 4253 SS11.2-11.4 allows these to be sent at any time;
/// previously AuthLayer treated any non-UserauthRequestMessage as a fatal
/// protocol error, disconnecting real-world clients that legitimately
/// interleave SSH_MSG_IGNORE with authentication traffic.
/// </summary>
public class AuthLayerIgnoreMessageTests
{
    private sealed class AlwaysAcceptAuthenticator : IAuthenticator
    {
        public IEnumerable<string> SupportedMethods => new[] { "password" };

        public ValueTask<(AuthResult Result, AuthenticatedUser? User)> AuthenticateAsync(
            AuthContext context, CancellationToken cancellationToken = default)
        {
            var user = new AuthenticatedUser { Username = context.Username, Method = context.Method };
            return ValueTask.FromResult<(AuthResult, AuthenticatedUser?)>((AuthResult.Success, user));
        }

        public ValueTask<bool> IsPublicKeyAcceptableAsync(
            string username, string algorithm, ReadOnlyMemory<byte> publicKeyBlob,
            CancellationToken cancellationToken = default) => ValueTask.FromResult(false);
    }

    private static async Task<(TcpListener listener, TcpClient client, NetworkStream serverStream, NetworkStream clientStream)> CreateLoopbackAsync()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var acceptTask = listener.AcceptTcpClientAsync();
        var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        var server = await acceptTask;
        return (listener, client, server.GetStream(), client.GetStream());
    }

    [Fact]
    public async Task AuthenticateAsync_IgnoresSshMsgIgnore_DuringAuthentication()
    {
        var (listener, client, serverStream, clientStream) = await CreateLoopbackAsync();
        try
        {
            var serverTransport = new TransportLayer(serverStream);
            var clientTransport = new TransportLayer(clientStream);

            // Minimal unencrypted "version exchange" substitute: both sides just
            // need _serverVersion/_clientVersion populated so packet framing works;
            // real key exchange is irrelevant to this test since no cipher is active.
            var serverExchange = serverTransport.ExchangeVersionsAsync("SSH-2.0-EmbeddedSshTest").AsTask();
            var clientExchange = clientTransport.ExchangeVersionsAsync("SSH-2.0-ClientTest").AsTask();
            await Task.WhenAll(serverExchange, clientExchange);

            var authLayer = new AuthLayer(serverTransport, new AlwaysAcceptAuthenticator());
            var authTask = authLayer.AuthenticateAsync().AsTask();

            // A well-behaved client (and OpenSSH in particular) may interleave
            // SSH_MSG_IGNORE with authentication traffic (RFC 4253 SS11.2). This
            // must not abort the handshake.
            await clientTransport.SendMessageAsync(new IgnoreMessage { Data = new byte[] { 1, 2, 3 } });
            await clientTransport.SendMessageAsync(new DebugMessage
            {
                AlwaysDisplay = false,
                Message = "keepalive",
                LanguageTag = ""
            });

            await clientTransport.SendMessageAsync(new UserauthRequestMessage
            {
                Username = "alice",
                ServiceName = "ssh-connection",
                MethodName = "password",
                Password = "hunter2"
            });

            var completed = await Task.WhenAny(authTask, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(authTask, completed);

            var authenticatedUser = await authTask;
            Assert.Equal("alice", authenticatedUser.Username);

            var response = await clientTransport.ReceiveMessageAsync();
            Assert.IsType<UserauthSuccessMessage>(response);
        }
        finally
        {
            client.Dispose();
            listener.Stop();
        }
    }
}
