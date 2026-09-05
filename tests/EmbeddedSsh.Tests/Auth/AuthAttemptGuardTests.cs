using d0x2a.EmbeddedSsh.Auth;

namespace d0x2a.EmbeddedSsh.Tests.Auth;

/// <summary>
/// Regression tests for AuthAttemptGuard: cross-connection, per-address
/// lockout that closes the gap where AuthLayer's per-connection
/// MaxAuthAttempts could be reset simply by reconnecting.
/// </summary>
public class AuthAttemptGuardTests
{
    [Fact]
    public void NewAddress_HasNoLockout()
    {
        var key = Guid.NewGuid().ToString();
        Assert.Equal(TimeSpan.Zero, AuthAttemptGuard.GetLockoutRemaining(key));
    }

    [Fact]
    public void RecordFailure_LocksOutAfterThreshold()
    {
        var key = Guid.NewGuid().ToString();

        // Below the threshold: not locked out yet.
        for (var i = 0; i < 29; i++)
            AuthAttemptGuard.RecordFailure(key);
        Assert.Equal(TimeSpan.Zero, AuthAttemptGuard.GetLockoutRemaining(key));

        // Crossing the threshold locks the address out.
        AuthAttemptGuard.RecordFailure(key);
        Assert.True(AuthAttemptGuard.GetLockoutRemaining(key) > TimeSpan.Zero);
    }

    [Fact]
    public void Clear_RemovesLockoutState()
    {
        var key = Guid.NewGuid().ToString();
        for (var i = 0; i < 30; i++)
            AuthAttemptGuard.RecordFailure(key);
        Assert.True(AuthAttemptGuard.GetLockoutRemaining(key) > TimeSpan.Zero);

        AuthAttemptGuard.Clear(key);
        Assert.Equal(TimeSpan.Zero, AuthAttemptGuard.GetLockoutRemaining(key));
    }

    [Fact]
    public void NullOrEmptyKey_NeverLocksOut()
    {
        // AuthLayer passes null when no remote endpoint was supplied
        // (e.g. tests/samples constructing SshConnection directly). The
        // guard must be a no-op in that case rather than throwing or
        // locking out a shared "null" bucket.
        for (var i = 0; i < 100; i++)
        {
            AuthAttemptGuard.RecordFailure(null);
            AuthAttemptGuard.RecordFailure(string.Empty);
        }
        Assert.Equal(TimeSpan.Zero, AuthAttemptGuard.GetLockoutRemaining(null));
        Assert.Equal(TimeSpan.Zero, AuthAttemptGuard.GetLockoutRemaining(string.Empty));
    }

    [Fact]
    public void DifferentAddresses_AreTrackedIndependently()
    {
        var keyA = Guid.NewGuid().ToString();
        var keyB = Guid.NewGuid().ToString();

        for (var i = 0; i < 30; i++)
            AuthAttemptGuard.RecordFailure(keyA);

        Assert.True(AuthAttemptGuard.GetLockoutRemaining(keyA) > TimeSpan.Zero);
        Assert.Equal(TimeSpan.Zero, AuthAttemptGuard.GetLockoutRemaining(keyB));
    }
}
