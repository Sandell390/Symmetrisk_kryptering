using System.Diagnostics;
using System.Security.Cryptography;

namespace Symmetrisk_kryptering_Backend;

public class DES_Encrypter : IEncrypter
{
     public string EncryptMethod { get; set; } = "DES_Encrypter";
        public int BlockSize { get; private set; }
        public int KeySize { get; private set; }
        public List<TimeSpan> TimeSpans { get; set; }

        public byte[] IV { get; set; }
        public byte[] Key { get; set; }
        public CipherMode Mode { get; private set; }
        
        public DES_Encrypter(CipherMode mode, int blockSize, int keySize)
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

            using (DES des = DES.Create())
            {
                des.BlockSize = BlockSize;
                des.KeySize = KeySize;
                des.Key = Key;
                des.IV = IV;
                des.Mode = Mode;
                
                ICryptoTransform decryptor = des.CreateDecryptor(des.Key, des.IV);
                
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
            
            using (DES des = DES.Create())
            {
                des.BlockSize = BlockSize;
                des.KeySize = KeySize;
                des.GenerateKey();
                des.GenerateIV();
                Key = des.Key;
                IV = des.IV;
                des.Mode = Mode;
                
                ICryptoTransform encryptor = des.CreateEncryptor(des.Key, des.IV);
                
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