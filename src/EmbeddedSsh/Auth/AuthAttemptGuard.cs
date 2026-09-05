using System.Collections.Concurrent;

namespace d0x2a.EmbeddedSsh.Auth;

/// <summary>
/// Cross-connection, per-remote-address authentication attempt tracking.
/// AuthLayer's own attempt counter only counts attempts within a single TCP
/// connection/AuthLayer instance, so a client can trivially reset its
/// attempt counter by reconnecting (or run many attempts in parallel via
/// <see cref="SshServerOptions.MaxConnections"/> concurrent connections),
/// turning the per-connection limit into brute-force amplification rather
/// than protection.
///
/// This is intentionally simple/in-memory: it complements (does not
/// replace) whatever attempt-limiting the embedding application does at
/// its own account/credential-store layer.
/// </summary>
internal static class AuthAttemptGuard
{
    private const int MaxAttempts = 30;
    private static readonly TimeSpan AttemptWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(10);

    private sealed class State
    {
        public int Count;
        public DateTimeOffset WindowStart;
        public DateTimeOffset? LockedUntil;
    }

    private static readonly ConcurrentDictionary<string, State> Attempts = new(StringComparer.Ordinal);

    /// <summary>Returns remaining lockout time, or TimeSpan.Zero if not locked.</summary>
    public static TimeSpan GetLockoutRemaining(string? key)
    {
        if (string.IsNullOrEmpty(key))
            return TimeSpan.Zero;

        if (!Attempts.TryGetValue(key, out var state))
            return TimeSpan.Zero;

        lock (state)
        {
            if (state.LockedUntil is { } until && until > DateTimeOffset.UtcNow)
                return until - DateTimeOffset.UtcNow;
        }

        return TimeSpan.Zero;
    }

    public static void RecordFailure(string? key)
    {
        if (string.IsNullOrEmpty(key))
            return;

        var state = Attempts.GetOrAdd(key, static _ => new State { WindowStart = DateTimeOffset.UtcNow });
        lock (state)
        {
            var now = DateTimeOffset.UtcNow;
            if (now - state.WindowStart > AttemptWindow)
            {
                state.Count = 0;
                state.WindowStart = now;
            }

            state.Count++;
            if (state.Count >= MaxAttempts)
                state.LockedUntil = now + LockoutDuration;
        }
    }

    public static void Clear(string? key)
    {
        if (string.IsNullOrEmpty(key))
            return;

        Attempts.TryRemove(key, out _);
    }
}
