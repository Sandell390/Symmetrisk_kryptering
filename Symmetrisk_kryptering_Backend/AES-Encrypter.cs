using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;
using System.Security.Cryptography;

namespace Symmetrisk_kryptering_Backend
{
    public class AES_Encrypter : IEncrypter
    {
        public string EncryptMethod { get; set; } = "AES_Encrypter";
        public int BlockSize { get; private set; }
        public int KeySize { get; private set; }
        public List<TimeSpan> TimeSpans { get; set; }

        public byte[] IV { get; set; }
        public byte[] Key { get; set; }
        public CipherMode Mode { get; private set; }

        public AES_Encrypter(CipherMode mode, int blockSize, int keySize)
        {
            Mode = mode;
            BlockSize = blockSize;
            KeySize = keySize;
            TimeSpans = new List<TimeSpan>();
        }

        public string Decrypt(byte[] cipherText)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            string plaintext;

            using (Aes aes = Aes.Create())
            {
                aes.BlockSize = BlockSize;
                aes.KeySize = KeySize;
                aes.Key = Key;
                aes.IV = IV;
                aes.Mode = Mode;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

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

            sw.Stop();
            TimeSpans.Add(sw.Elapsed);
            return plaintext;
        }

        public byte[] Encrypt(string plainText)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            byte[] encrypted;

            using (Aes aes = Aes.Create())
            {
                aes.BlockSize = BlockSize;
                aes.KeySize = KeySize;
                aes.GenerateKey();
                aes.GenerateIV();
                Key = aes.Key;
                IV = aes.IV;
                aes.Mode = Mode;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

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
            sw.Stop();
            TimeSpans.Add(sw.Elapsed);
            return encrypted;
        }
    }
}
