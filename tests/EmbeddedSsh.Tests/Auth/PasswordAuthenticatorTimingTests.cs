using d0x2a.EmbeddedSsh.Auth;

namespace d0x2a.EmbeddedSsh.Tests.Auth;

/// <summary>
/// Regression tests for PasswordAuthenticator's dictionary-based constructor:
/// an unknown username must be rejected via the same code path (a
/// FixedTimeEquals comparison against a dummy value) as a known username with
/// a wrong password, instead of short-circuiting to `false` immediately -
/// which previously created a timing side-channel that could be used to
/// enumerate valid usernames.
/// </summary>
public class PasswordAuthenticatorTimingTests
{
    private static AuthContext MakeContext(string username, string password) => new()
    {
        Username = username,
        ServiceName = "ssh-connection",
        Method = "password",
        SessionId = [],
        Password = password,
    };

    [Fact]
    public async Task UnknownUsername_Fails()
    {
        var auth = new PasswordAuthenticator(new Dictionary<string, string> { ["alice"] = "correct-horse" });
        var (result, user) = await auth.AuthenticateAsync(MakeContext("bob", "anything"));
        Assert.Equal(AuthResult.Failure, result);
        Assert.Null(user);
    }

    [Fact]
    public async Task KnownUsername_WrongPassword_Fails()
    {
        var auth = new PasswordAuthenticator(new Dictionary<string, string> { ["alice"] = "correct-horse" });
        var (result, user) = await auth.AuthenticateAsync(MakeContext("alice", "wrong-password"));
        Assert.Equal(AuthResult.Failure, result);
        Assert.Null(user);
    }

    [Fact]
    public async Task KnownUsername_CorrectPassword_Succeeds()
    {
        var auth = new PasswordAuthenticator(new Dictionary<string, string> { ["alice"] = "correct-horse" });
        var (result, user) = await auth.AuthenticateAsync(MakeContext("alice", "correct-horse"));
        Assert.Equal(AuthResult.Success, result);
        Assert.NotNull(user);
        Assert.Equal("alice", user!.Username);
    }

    [Fact]
    public async Task UnknownAndWrongPassword_TakeComparableTime()
    {
        // Not a precise timing-attack proof (that needs statistical
        // measurement over many samples in a controlled environment), but a
        // basic sanity check that the unknown-user path no longer returns
        // near-instantly compared to the wrong-password path - i.e. it
        // actually performs a comparable amount of work (a FixedTimeEquals
        // call) rather than short-circuiting.
        var auth = new PasswordAuthenticator(new Dictionary<string, string> { ["alice"] = "correct-horse-battery-staple" });

        const int iterations = 500;
        var swUnknown = System.Diagnostics.Stopwatch.StartNew();
        for (var i = 0; i < iterations; i++)
            await auth.AuthenticateAsync(MakeContext("no-such-user", "guess-guess-guess"));
        swUnknown.Stop();

        var swWrongPassword = System.Diagnostics.Stopwatch.StartNew();
        for (var i = 0; i < iterations; i++)
            await auth.AuthenticateAsync(MakeContext("alice", "guess-guess-guess"));
        swWrongPassword.Stop();

        // Both paths should now do "real" work; assert neither is
        // suspiciously many times faster than the other (loose bound - this
        // is a smoke test, not a cryptographic timing proof).
        var ratio = (double)swUnknown.ElapsedTicks / Math.Max(1, swWrongPassword.ElapsedTicks);
        Assert.InRange(ratio, 0.2, 5.0);
    }
}
