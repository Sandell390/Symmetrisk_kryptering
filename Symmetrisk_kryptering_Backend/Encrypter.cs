using System.Diagnostics;
using System.Security.Cryptography;

namespace Symmetrisk_kryptering_Backend;

public class Encrypter
{
    public int BlockSize { get; set; }
    public int KeySize { get; set; }
    public List<TimeSpan> TimeSpans { get; }
    private byte[] IV;
    private byte[] Key;
    public CipherMode Mode { get; set; }
    
    private SymmetricAlgorithm _symmetricAlgorithm;
    
    public KeySizes LegacyKeySize { get; private set; }
    public KeySizes LegacyBlockSize { get; private set; }
    
    public Algorithm AlgorithmType { get; private set; }
    
    public enum Algorithm
    {
        Aes = 1,
        TripleDes = 2,
        Des = 3,
    }

    public Encrypter(Algorithm algorithm)
    {
        AlgorithmType = algorithm;
        switch (algorithm)
        {
            case Algorithm.Aes:
                _symmetricAlgorithm = Aes.Create();
                break;
            case Algorithm.TripleDes:
                _symmetricAlgorithm = TripleDES.Create();
                break;
            case Algorithm.Des:
                _symmetricAlgorithm = DES.Create();
                break;
            default:
                _symmetricAlgorithm = Aes.Create();
                break;
        }
        
        TimeSpans = new List<TimeSpan>();
        LegacyBlockSize = _symmetricAlgorithm.LegalBlockSizes[0];
        LegacyKeySize = _symmetricAlgorithm.LegalKeySizes[0];
    }
    
    public string Decrypt(byte[] cipherText)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            string plaintext;

            _symmetricAlgorithm.Mode = Mode;
            _symmetricAlgorithm.BlockSize = BlockSize;
            _symmetricAlgorithm.KeySize = KeySize;
            _symmetricAlgorithm.Key = Key;
            _symmetricAlgorithm.IV = IV;
            
            ICryptoTransform decryptor = _symmetricAlgorithm.CreateDecryptor(_symmetricAlgorithm.Key, _symmetricAlgorithm.IV);

            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }

            sw.Stop();
            TimeSpans.Add(sw.Elapsed);
            return plaintext;
        }

        public byte[] Encrypt(string plainText)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            byte[] encrypted;

            _symmetricAlgorithm.Mode = Mode;
            _symmetricAlgorithm.BlockSize = BlockSize;
            _symmetricAlgorithm.KeySize = KeySize;
            _symmetricAlgorithm.GenerateIV();
            _symmetricAlgorithm.GenerateKey();
            IV = _symmetricAlgorithm.IV;
            Key = _symmetricAlgorithm.Key;
            ICryptoTransform encryptor = _symmetricAlgorithm.CreateEncryptor(_symmetricAlgorithm.Key, _symmetricAlgorithm.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }

                    encrypted = msEncrypt.ToArray();
                }
            }

            sw.Stop();
            TimeSpans.Add(sw.Elapsed);
            return encrypted;
        }
}