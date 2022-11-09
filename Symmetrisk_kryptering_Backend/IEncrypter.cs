using System.Security.Cryptography;

namespace Symmetrisk_kryptering_Backend;

public interface IEncrypter
{
    public string EncryptMethod { get; set; }
    public int BlockSize { get;}
    public int KeySize { get; }
    public List<TimeSpan> TimeSpans { get;}
    public byte[] IV { get; }
    public byte[] Key { get; }
    public CipherMode Mode { get; }

    public string Decrypt(byte[] cipherText);

    public byte[] Encrypt(string plainText);

}