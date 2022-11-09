using System.Security.Cryptography;
using Symmetrisk_kryptering_Backend;

Console.WriteLine("--- Symmetrisk kryptering ---");

List<IEncrypter> encrypters = new List<IEncrypter>();

//encrypters.Add(new AES_Encrypter(CipherMode.CBC, 256, 16));
encrypters.Add(new AES_Encrypter(CipherMode.CBC, 128, 128));
//encrypters.Add(new AES_Encrypter(CipherMode.CBC, 192, 16));

//encrypters.Add(new AES_Encrypter(CipherMode.ECB, 256, 16));
encrypters.Add(new AES_Encrypter(CipherMode.ECB, 128, 128));
//encrypters.Add(new AES_Encrypter(CipherMode.ECB, 192, 16));

encrypters.Add(new DES_Encrypter(CipherMode.CBC, 64, 64));
encrypters.Add(new DES_Encrypter(CipherMode.ECB, 64, 64));

encrypters.Add(new TripleDES_Encrypter(CipherMode.CBC, 64, 192));
encrypters.Add(new TripleDES_Encrypter(CipherMode.ECB, 64, 192));

foreach (var encrypter in encrypters)
{
    byte[] encrypted = encrypter.Encrypt("Hello World!");
    string decrypted = encrypter.Decrypt(encrypted);
    Console.WriteLine("Encrypter: " + encrypter.EncryptMethod);
    Console.WriteLine("Encrypted: " + Convert.ToBase64String(encrypted));
    Console.WriteLine("Decrypted: " + decrypted);
    Console.WriteLine("Blocksize: " + encrypter.BlockSize);
    Console.WriteLine("Keysize: " + encrypter.KeySize);
    Console.WriteLine("Ciphermode: " + encrypter.Mode);
    Console.WriteLine("Encryption time: " + encrypter.TimeSpans[0]);
    Console.WriteLine("Decryption time: " + encrypter.TimeSpans[1]);
    Console.WriteLine("--------------------------------");
}


Console.Read();
