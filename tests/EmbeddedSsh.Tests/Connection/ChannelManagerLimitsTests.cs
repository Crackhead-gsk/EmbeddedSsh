using System.Net;
using System.Net.Sockets;
using d0x2a.EmbeddedSsh.Connection;

namespace d0x2a.EmbeddedSsh.Tests.Connection;

/// <summary>
/// Regression tests for ChannelManager's channel-count cap and the
/// MaximumPacketSize integer-overflow clamp in SshChannel.
///
/// Previously there was no limit on concurrently open channels per
/// connection, and MaxPacketSize was stored as-is from a client-controlled
/// uint, which becomes negative when cast to int for values > int.MaxValue
/// (e.g. 0xFFFFFFFF), crashing Math.Min/Slice arithmetic in SshChannel.WriteAsync.
/// </summary>
public class ChannelManagerLimitsTests : IDisposable
{
    private readonly TcpListener _listener;
    private readonly TcpClient _client;
    private readonly d0x2a.EmbeddedSsh.Transport.TransportLayer _transport;

    public ChannelManagerLimitsTests()
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        var acceptTask = _listener.AcceptTcpClientAsync();
        _client = new TcpClient();
        _client.Connect(IPAddress.Loopback, ((IPEndPoint)_listener.LocalEndpoint).Port);
        var server = acceptTask.GetAwaiter().GetResult();
        _transport = new d0x2a.EmbeddedSsh.Transport.TransportLayer(server.GetStream());
    }

    public void Dispose()
    {
        _client.Dispose();
        _listener.Stop();
    }

    [Fact]
    public void HasCapacityForNewChannel_FalseOnceMaxChannelsReached()
    {
        var manager = new ChannelManager { MaxChannels = 2 };
        Assert.True(manager.HasCapacityForNewChannel());

        var c1 = new SshChannel(_transport, manager, manager.AllocateChannelId(), "session", ChannelManager.DefaultWindowSize);
        manager.RegisterChannel(c1);
        Assert.True(manager.HasCapacityForNewChannel());

        var c2 = new SshChannel(_transport, manager, manager.AllocateChannelId(), "session", ChannelManager.DefaultWindowSize);
        manager.RegisterChannel(c2);
        Assert.False(manager.HasCapacityForNewChannel());

        manager.RemoveChannel(c1.LocalChannelId);
        Assert.True(manager.HasCapacityForNewChannel());
    }

    [Fact]
    public void DefaultMaxChannels_IsPositiveAndBounded()
    {
        // Sanity check the default itself is a real cap, not accidentally
        // unbounded (e.g. int.MaxValue) or zero (which would break all
        // legitimate multi-channel usage).
        Assert.InRange(ChannelManager.DefaultMaxChannels, 1, 10_000);
    }

    [Theory]
    [InlineData(0xFFFFFFFFu)]
    [InlineData((uint)int.MaxValue + 1)]
    public void ConfirmOpen_ClampsOversizedMaxPacketSize(uint maliciousMaxPacketSize)
    {
        var manager = new ChannelManager();
        var channel = new SshChannel(_transport, manager, manager.AllocateChannelId(), "session", ChannelManager.DefaultWindowSize);

        channel.ConfirmOpen(remoteChannelId: 1, remoteWindow: 1024, maxPacketSize: maliciousMaxPacketSize);

        // Must never exceed int.MaxValue: WriteAsync casts MaxPacketSize to
        // `int` for Math.Min/Slice arithmetic, and a value above that would
        // become negative after the cast.
        Assert.True(channel.MaxPacketSize <= int.MaxValue);
        Assert.True((int)channel.MaxPacketSize >= 0);
    }

    [Fact]
    public void ConfirmOpen_PreservesReasonableMaxPacketSize()
    {
        var manager = new ChannelManager();
        var channel = new SshChannel(_transport, manager, manager.AllocateChannelId(), "session", ChannelManager.DefaultWindowSize);

        channel.ConfirmOpen(remoteChannelId: 1, remoteWindow: 1024, maxPacketSize: ChannelManager.DefaultMaxPacketSize);

        Assert.Equal(ChannelManager.DefaultMaxPacketSize, channel.MaxPacketSize);
    }
}
