using System.Security.Cryptography;
using d0x2a.EmbeddedSsh.Crypto;

namespace d0x2a.EmbeddedSsh.Tests.Crypto;

public class CryptoTests
{
    #region ChaCha20 Tests (RFC 7539)

    [Fact]
    public void ChaCha20_TestVector1()
    {
        // RFC 7539 Section 2.4.2 Test Vector
        var key = Convert.FromHexString(
            "000102030405060708090a0b0c0d0e0f" +
            "101112131415161718191a1b1c1d1e1f");
        var nonce = Convert.FromHexString("000000000000004a00000000");
        var plaintext = Convert.FromHexString(
            "4c616469657320616e642047656e746c" +
            "656d656e206f662074686520636c6173" +
            "73206f66202739393a20496620492063" +
            "6f756c64206f6666657220796f75206f" +
            "6e6c79206f6e652074697020666f7220" +
            "746865206675747572652c2073756e73" +
            "637265656e20776f756c642062652069" +
            "742e");
        var expected = Convert.FromHexString(
            "6e2e359a2568f98041ba0728dd0d6981" +
            "e97e7aec1d4360c20a27afccfd9fae0b" +
            "f91b65c5524733ab8f593dabcd62b357" +
            "1639d624e65152ab8f530c359f0861d8" +
            "07ca0dbf500d6a6156a38e088a22b65e" +
            "52bc514d16ccf806818ce91ab7793736" +
            "5af90bbf74a35be6b40b8eedf2785e42" +
            "874d");

        var ciphertext = new byte[plaintext.Length];
        ChaCha20.Process(key, nonce, 1, plaintext, ciphertext);

        Assert.Equal(expected, ciphertext);
    }

    [Fact]
    public void ChaCha20_Block_TestVector()
    {
        // RFC 7539 Section 2.3.2
        var key = Convert.FromHexString(
            "000102030405060708090a0b0c0d0e0f" +
            "101112131415161718191a1b1c1d1e1f");
        var nonce = Convert.FromHexString("000000090000004a00000000");

        var output = new byte[64];
        ChaCha20.Block(key, nonce, 1, output);

        var expected = Convert.FromHexString(
            "10f1e7e4d13b5915500fdd1fa32071c4" +
            "c7d1f4c733c068030422aa9ac3d46c4e" +
            "d2826446079faa0914c2d705d98b02a2" +
            "b5129cd1de164eb9cbd083e8a2503c4e");

        Assert.Equal(expected, output);
    }

    [Fact]
    public void ChaCha20_RoundTrip()
    {
        var key = new byte[32];
        var nonce = new byte[12];
        Random.Shared.NextBytes(key);
        Random.Shared.NextBytes(nonce);

        var plaintext = "Hello, ChaCha20!"u8.ToArray();
        var ciphertext = new byte[plaintext.Length];
        var decrypted = new byte[plaintext.Length];

        ChaCha20.Process(key, nonce, 0, plaintext, ciphertext);
        ChaCha20.Process(key, nonce, 0, ciphertext, decrypted);

        Assert.Equal(plaintext, decrypted);
    }

    #endregion

    #region Poly1305 Tests (RFC 7539)

    [Fact]
    public void Poly1305_TestVector1()
    {
        // RFC 7539 Section 2.5.2
        var key = Convert.FromHexString(
            "85d6be7857556d337f4452fe42d506a8" +
            "0103808afb0db2fd4abff6af4149f51b");
        var message = Convert.FromHexString(
            "43727970746f6772617068696320466f" +
            "72756d2052657365617263682047726f" +
            "7570");
        var expected = Convert.FromHexString("a8061dc1305136c6c22b8baf0c0127a9");

        var tag = Poly1305.ComputeTag(key, message);

        Assert.Equal(expected, tag);
    }

    [Fact]
    public void Poly1305_Verify()
    {
        var key = Convert.FromHexString(
            "85d6be7857556d337f4452fe42d506a8" +
            "0103808afb0db2fd4abff6af4149f51b");
        var message = Convert.FromHexString(
            "43727970746f6772617068696320466f" +
            "72756d2052657365617263682047726f" +
            "7570");
        var tag = Convert.FromHexString("a8061dc1305136c6c22b8baf0c0127a9");

        Assert.True(Poly1305.Verify(key, message, tag));

        // Modify tag and verify it fails
        tag[0] ^= 1;
        Assert.False(Poly1305.Verify(key, message, tag));
    }

    #endregion

    #region X25519 Tests (RFC 7748)

    [Fact]
    public void X25519_TestVector1()
    {
        // RFC 7748 Section 6.1
        var alicePrivate = Convert.FromHexString(
            "77076d0a7318a57d3c16c17251b26645" +
            "df4c2f87ebc0992ab177fba51db92c2a");
        var alicePublic = Convert.FromHexString(
            "8520f0098930a754748b7ddcb43ef75a" +
            "0dbf3a0d26381af4eba4a98eaa9b4e6a");

        var computed = X25519.GetPublicKey(alicePrivate);
        Assert.Equal(alicePublic, computed);
    }

    [Fact]
    public void X25519_TestVector2()
    {
        // RFC 7748 Section 6.1 - Shared secret
        var alicePrivate = Convert.FromHexString(
            "77076d0a7318a57d3c16c17251b26645" +
            "df4c2f87ebc0992ab177fba51db92c2a");
        var bobPublic = Convert.FromHexString(
            "de9edb7d7b7dc1b4d35b61c2ece43537" +
            "3f8343c85b78674dadfc7e146f882b4f");
        var expectedShared = Convert.FromHexString(
            "4a5d9d5ba4ce2de1728e3bf480350f25" +
            "e07e21c947d19e3376f09b3c1e161742");

        var shared = X25519.ComputeSharedSecret(alicePrivate, bobPublic);
        Assert.Equal(expectedShared, shared);
    }

    [Fact]
    public void X25519_KeyExchange()
    {
        // Generate key pairs
        var (alicePrivate, alicePublic) = X25519.GenerateKeyPair();
        var (bobPrivate, bobPublic) = X25519.GenerateKeyPair();

        // Compute shared secrets
        var aliceShared = X25519.ComputeSharedSecret(alicePrivate, bobPublic);
        var bobShared = X25519.ComputeSharedSecret(bobPrivate, alicePublic);

        Assert.Equal(aliceShared, bobShared);
    }

    #endregion

    #region Ed25519 Tests (RFC 8032)

    [Fact]
    public void Ed25519_TestVector1_EmptyMessage()
    {
        // RFC 8032 Section 7.1 Test 1
        var privateKey = Convert.FromHexString(
            "9d61b19deffd5a60ba844af492ec2cc4" +
            "4449c5697b326919703bac031cae7f60");
        var expectedPublic = Convert.FromHexString(
            "d75a980182b10ab7d54bfed3c964073a" +
            "0ee172f3daa62325af021a68f707511a");
        var expectedSignature = Convert.FromHexString(
            "e5564300c360ac729086e2cc806e828a" +
            "84877f1eb8e5d974d873e065224901555" +
            "fb8821590a33bacc61e39701cf9b46bd" +
            "25bf5f0595bbe24655141438e7a100b");

        var publicKey = Ed25519.GetPublicKey(privateKey);
        Assert.Equal(expectedPublic, publicKey);

        var signature = Ed25519.Sign(privateKey, ReadOnlySpan<byte>.Empty);
        Assert.Equal(expectedSignature, signature);

        Assert.True(Ed25519.Verify(publicKey, ReadOnlySpan<byte>.Empty, signature));
    }

    [Fact]
    public void Ed25519_TestVector2_OneByte()
    {
        // RFC 8032 Section 7.1 Test 2
        var privateKey = Convert.FromHexString(
            "4ccd089b28ff96da9db6c346ec114e0f" +
            "5b8a319f35aba624da8cf6ed4fb8a6fb");
        var expectedPublic = Convert.FromHexString(
            "3d4017c3e843895a92b70aa74d1b7ebc" +
            "9c982ccf2ec4968cc0cd55f12af4660c");
        var message = new byte[] { 0x72 };
        var expectedSignature = Convert.FromHexString(
            "92a009a9f0d4cab8720e820b5f642540" +
            "a2b27b5416503f8fb3762223ebdb69da" +
            "085ac1e43e15996e458f3613d0f11d8c" +
            "387b2eaeb4302aeeb00d291612bb0c00");

        var publicKey = Ed25519.GetPublicKey(privateKey);
        Assert.Equal(expectedPublic, publicKey);

        var signature = Ed25519.Sign(privateKey, message);
        Assert.Equal(expectedSignature, signature);

        Assert.True(Ed25519.Verify(publicKey, message, signature));
    }

    [Fact]
    public void Ed25519_SignVerify_RoundTrip()
    {
        var (privateKey, publicKey) = Ed25519.GenerateKeyPair();
        var message = "Hello, Ed25519!"u8.ToArray();

        var signature = Ed25519.Sign(privateKey, message);
        Assert.True(Ed25519.Verify(publicKey, message, signature));

        // Modify message and verify it fails
        message[0] ^= 1;
        Assert.False(Ed25519.Verify(publicKey, message, signature));
    }

    [Fact]
    public void Ed25519_InvalidSignature_Fails()
    {
        var (privateKey, publicKey) = Ed25519.GenerateKeyPair();
        var message = "Test message"u8.ToArray();

        var signature = Ed25519.Sign(privateKey, message);

        // Modify signature
        signature[0] ^= 1;
        Assert.False(Ed25519.Verify(publicKey, message, signature));
    }

    [Fact]
    public void Ed25519_TestVector3_LongerMessage()
    {
        // RFC 8032 Section 7.1 Test 3 (SHA(abc) test case), exercised here
        // primarily to cover more/different key-scalar bit patterns than
        // Test 1/2 in the constant-time ScalarMultBase rewrite.
        var privateKey = Convert.FromHexString(
            "c5aa8df43f9f837bedb7442f31dcb7b1" +
            "66d38535076f094b85ce3a2e0b4458f7");
        var expectedPublic = Convert.FromHexString(
            "fc51cd8e6218a1a38da47ed00230f058" +
            "0816ed13ba3303ac5deb911548908025");
        var message = Convert.FromHexString(
            "af82");
        var expectedSignature = Convert.FromHexString(
            "6291d657deec24024827e69c3abe01a3" +
            "0ce548a284743a445e3680d7db5ac3ac" +
            "18ff9b538d16f290ae67f760984dc659" +
            "4a7c15e9716ed28dc027beceea1ec40a");

        var publicKey = Ed25519.GetPublicKey(privateKey);
        Assert.Equal(expectedPublic, publicKey);

        var signature = Ed25519.Sign(privateKey, message);
        Assert.Equal(expectedSignature, signature);

        Assert.True(Ed25519.Verify(publicKey, message, signature));
    }

    [Fact]
    public void Ed25519_ManyRandomRoundTrips_AllVerify()
    {
        // Stress test for the constant-time ScalarMultBase rewrite: many
        // random keys/messages exercise a wide spread of scalar bit
        // patterns (the old branchy code and the new branchless PointCSelect
        // code must agree on every bit pattern, not just the fixed RFC
        // vectors above).
        for (var i = 0; i < 200; i++)
        {
            var (privateKey, publicKey) = Ed25519.GenerateKeyPair();
            var message = RandomNumberGenerator.GetBytes(1 + (i % 64));

            var signature = Ed25519.Sign(privateKey, message);
            Assert.True(Ed25519.Verify(publicKey, message, signature));

            // Corrupting the message must always invalidate the signature.
            message[0] ^= 0xFF;
            Assert.False(Ed25519.Verify(publicKey, message, signature));
        }
    }

    #endregion
}
