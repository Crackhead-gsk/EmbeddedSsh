using System.Net;
using System.Net.Sockets;
using d0x2a.EmbeddedSsh.Connection;
using d0x2a.EmbeddedSsh.Protocol.Messages;
using d0x2a.EmbeddedSsh.Transport;

namespace d0x2a.EmbeddedSsh.Tests.Connection;

/// <summary>
/// Regression tests for ConnectionLayer's SSH_MSG_CHANNEL_SUCCESS/FAILURE replies.
///
/// RFC 4254 SS5.4 requires CHANNEL_SUCCESS/FAILURE to carry the *recipient's* (i.e. the
/// client's) channel number for the channel in question. ConnectionLayer previously echoed
/// back the channel number from the incoming ChannelRequestMessage.RecipientChannel, which is
/// the *server's own local* channel id (used to look the channel up in ChannelManager) — not
/// the client's remote id. Client and server allocate channel ids independently, so whenever
/// they diverge (anything other than both happening to be 0 for the first channel), the
/// server ends up replying with a channel number the client never opened, and RFC-compliant
/// clients disconnect with "Received SSH2_MSG_CHANNEL_SUCCESS for nonexistent channel N".
/// </summary>
public class ConnectionLayerChannelReplyTests
{
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
    public async Task ChannelRequestSuccess_UsesClientChannelId_NotServerLocalId()
    {
        var (listener, client, serverStream, clientStream) = await CreateLoopbackAsync();
        try
        {
            var serverTransport = new TransportLayer(serverStream);
            var clientTransport = new TransportLayer(clientStream);

            var serverExchange = serverTransport.ExchangeVersionsAsync("SSH-2.0-EmbeddedSshTest").AsTask();
            var clientExchange = clientTransport.ExchangeVersionsAsync("SSH-2.0-ClientTest").AsTask();
            await Task.WhenAll(serverExchange, clientExchange);

            var connectionLayer = new ConnectionLayer(serverTransport);
            connectionLayer.ChannelRequestReceived += (_, request, _) =>
                ValueTask.FromResult(request.RequestType == "subsystem");

            var processLoop = Task.Run(async () =>
            {
                while (true)
                {
                    var message = await serverTransport.ReceiveMessageAsync();
                    await connectionLayer.ProcessMessageAsync(message);
                }
            });

            // Client deliberately allocates a *non-zero* local channel id, distinct from
            // whatever id the server picks for its own bookkeeping, so a bug that echoes the
            // server's internal id back would be caught even on the very first channel.
            const uint clientChannelId = 7;

            await clientTransport.SendMessageAsync(new ChannelOpenMessage
            {
                ChannelType = "session",
                SenderChannel = clientChannelId,
                InitialWindowSize = ChannelManager.DefaultWindowSize,
                MaximumPacketSize = ChannelManager.DefaultMaxPacketSize
            });

            var openReplyTask = clientTransport.ReceiveMessageAsync().AsTask();
            var completedOpen = await Task.WhenAny(openReplyTask, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(openReplyTask, completedOpen);
            var openReply = await openReplyTask;
            var confirmation = Assert.IsType<ChannelOpenConfirmationMessage>(openReply);
            Assert.Equal(clientChannelId, confirmation.RecipientChannel);

            var serverChannelId = confirmation.SenderChannel;

            await clientTransport.SendMessageAsync(new ChannelRequestMessage
            {
                RecipientChannel = serverChannelId, // client always addresses the server's id
                RequestType = "subsystem",
                WantReply = true,
                RequestData = BuildSubsystemRequestData("sftp")
            });

            var successReplyTask = clientTransport.ReceiveMessageAsync().AsTask();
            var completedSuccess = await Task.WhenAny(successReplyTask, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(successReplyTask, completedSuccess);
            var successReply = await successReplyTask;
            var success = Assert.IsType<ChannelSuccessMessage>(successReply);

            // This is the actual regression assertion: the reply must be addressed to the
            // *client's* channel id (clientChannelId), never to the server's internal id.
            Assert.Equal(clientChannelId, success.RecipientChannel);
        }
        finally
        {
            client.Dispose();
            listener.Stop();
        }
    }

    private static byte[] BuildSubsystemRequestData(string subsystemName)
    {
        var nameBytes = System.Text.Encoding.UTF8.GetBytes(subsystemName);
        var buffer = new byte[4 + nameBytes.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer, (uint)nameBytes.Length);
        nameBytes.CopyTo(buffer.AsSpan(4));
        return buffer;
    }
}
