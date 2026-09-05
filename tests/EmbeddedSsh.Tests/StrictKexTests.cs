using System.Reflection;
using d0x2a.EmbeddedSsh.Protocol.Messages;

namespace d0x2a.EmbeddedSsh.Tests;

/// <summary>
/// Regression tests for the Terrapin attack (CVE-2023-48795) countermeasure: OpenSSH's
/// "strict KEX" extension. These use reflection because CreateKexInit/NegotiateAlgorithms are
/// private static members of SshConnection with no public surface — a full end-to-end
/// handshake test (real client-side X25519/Ed25519 exchange) would exercise the same code
/// paths but is exactly what's already covered manually against real OpenSSH clients; these
/// tests pin down the two properties that matter for the countermeasure itself.
/// </summary>
public class StrictKexTests
{
    [Fact]
    public void CreateKexInit_AdvertisesStrictKexMarker()
    {
        var method = typeof(SshConnection).GetMethod(
            "CreateKexInit", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var kexInit = (KexInitMessage)method!.Invoke(null, null)!;

        Assert.Contains("kex-strict-s-v00@openssh.com", kexInit.KexAlgorithms);
    }

    [Fact]
    public void NegotiateAlgorithms_IgnoresStrictKexMarker_NeverSelectsItAsRealKex()
    {
        var method = typeof(SshConnection).GetMethod(
            "NegotiateAlgorithms", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        // A client that (like OpenSSH) advertises the strict-kex marker ahead of its real,
        // usable KEX algorithms. If NegotiateAlgorithms treated the marker as a selectable
        // algorithm, this would either throw (no IKexAlgorithm implementation for it) or
        // silently negotiate a KEX method the connection can't actually perform.
        var clientKexInit = new KexInitMessage
        {
            Cookie = new byte[16],
            KexAlgorithms = ["kex-strict-c-v00@openssh.com", "curve25519-sha256"],
            HostKeyAlgorithms = ["ssh-ed25519"],
            EncryptionAlgorithmsClientToServer = ["chacha20-poly1305@openssh.com"],
            EncryptionAlgorithmsServerToClient = ["chacha20-poly1305@openssh.com"],
            MacAlgorithmsClientToServer = ["hmac-sha2-256"],
            MacAlgorithmsServerToClient = ["hmac-sha2-256"],
            CompressionAlgorithmsClientToServer = ["none"],
            CompressionAlgorithmsServerToClient = ["none"],
            LanguagesClientToServer = [],
            LanguagesServerToClient = [],
            FirstKexPacketFollows = false
        };

        var result = ((string kex, string hostKey, string cipherC2S, string cipherS2C))
            method!.Invoke(null, [clientKexInit])!;

        Assert.Equal("curve25519-sha256", result.kex);
        Assert.NotEqual("kex-strict-c-v00@openssh.com", result.kex);
    }
}
