using System.Diagnostics;
using System.Security.Cryptography;

namespace Symmetrisk_kryptering_Backend;

public class TripleDES_Encrypter : IEncrypter
{
        public string EncryptMethod { get; set; } = "TripleDES_Encrypter";
        public int BlockSize { get; private set; }
        public int KeySize { get; private set; }
        public List<TimeSpan> TimeSpans { get; set; }

        public byte[] IV { get; set; }
        public byte[] Key { get; set; }
        public CipherMode Mode { get; private set; }
        
        public TripleDES_Encrypter(CipherMode mode, int blockSize, int keySize)
        {
            Mode = mode;
            BlockSize = blockSize;
            KeySize = keySize;
            TimeSpans = new List<TimeSpan>();
        }

        public string Decrypt(byte[] cipherText)
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            string plaintext;

            using (TripleDES tripleDes = TripleDES.Create())
            {
                tripleDes.BlockSize = BlockSize;
                tripleDes.KeySize = KeySize;
                tripleDes.Key = Key;
                tripleDes.IV = IV;
                tripleDes.Mode = Mode;
                
                ICryptoTransform decryptor = tripleDes.CreateDecryptor(tripleDes.Key, tripleDes.IV);
                
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
            }
            
            stopwatch.Stop();
            TimeSpans.Add(stopwatch.Elapsed);
            return plaintext;
        }
    
        public byte[] Encrypt(string plainText)
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            byte[] encrypted;
            
            using (TripleDES tripleDes = TripleDES.Create())
            {
                tripleDes.BlockSize = BlockSize;
                tripleDes.KeySize = KeySize;
                tripleDes.GenerateKey();
                tripleDes.GenerateIV();
                Key = tripleDes.Key;
                IV = tripleDes.IV;
                tripleDes.Mode = Mode;
                
                ICryptoTransform encryptor = tripleDes.CreateEncryptor(tripleDes.Key, tripleDes.IV);
                
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
                
            }
            
            stopwatch.Stop();
            TimeSpans.Add(stopwatch.Elapsed);
            return encrypted;
        }
}