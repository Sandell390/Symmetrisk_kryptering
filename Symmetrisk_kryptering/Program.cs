using System.Security.Cryptography;
using Symmetrisk_kryptering_Backend;

bool power = false;
do
{
    Console.Clear();
    Console.WriteLine("--- Symmetric Encrypting ---");
    Console.WriteLine();
    Console.WriteLine();

    // Choosing an algorithm
    Console.WriteLine("Choose an algorithm to use:");
    for (int i = 0; i < Enum.GetValues(typeof(Encrypter.Algorithm)).Length; i++)
    {
        Console.WriteLine($"{i + 1}: {Enum.GetValues(typeof(Encrypter.Algorithm)).GetValue(i)}");
    }

    Console.Write("Algorithm: ");
    int algorithm = ValidateInputInt(0, Enum.GetValues(typeof(Encrypter.Algorithm)).Length);

    Encrypter encrypter = new Encrypter((Encrypter.Algorithm)algorithm);


    // Choosing a cipher mode
    Console.WriteLine();
    Console.WriteLine("Choose a mode to use:");
    for (int i = 0; i < Enum.GetValues(typeof(CipherMode)).Length; i++)
    {
        Console.WriteLine($"{i + 1}: {Enum.GetValues(typeof(CipherMode)).GetValue(i)}");
    }

    Console.Write("Mode: ");
    int mode = ValidateInputInt(1, Enum.GetValues(typeof(CipherMode)).Length + 1);

    encrypter.Mode = (CipherMode)mode;


    // Choosing a KeySize
    Console.WriteLine();
    Console.WriteLine("Choose a key size to use:");
    int KeySizeSkips = 0; 
    if ((encrypter.LegacyKeySize.MaxSize - encrypter.LegacyKeySize.MinSize) == 0)
    {
        Console.WriteLine($"1: {encrypter.LegacyKeySize.MinSize}");
        KeySizeSkips++; 
    }
    else
    {
        KeySizeSkips = (encrypter.LegacyKeySize.MaxSize - encrypter.LegacyKeySize.MinSize) /
                       encrypter.LegacyKeySize.SkipSize;
        
        for (int i = 0; i < KeySizeSkips + 1; i++)
        {
            Console.WriteLine($"{i + 1}: {encrypter.LegacyKeySize.MinSize + (i * encrypter.LegacyKeySize.SkipSize)}");
        }
        KeySizeSkips++; // Adding 1 to the KeySizeSkips to account for the first option
    }

    Console.Write("Key size: ");
    int keySize = ValidateInputInt(1, KeySizeSkips);
    keySize--; // Subtracting 1 to account for the first option
    encrypter.KeySize = encrypter.LegacyKeySize.MinSize + (keySize * encrypter.LegacyKeySize.SkipSize);


    // Choosing a BlockSize
    Console.WriteLine();
    Console.WriteLine("Choose a block size to use:");
    int BlockSizeSkips = 0;
    if ((encrypter.LegacyBlockSize.MaxSize - encrypter.LegacyBlockSize.MinSize) == 0)
    {
        Console.WriteLine($"1: {encrypter.LegacyBlockSize.MinSize}");
        BlockSizeSkips++;
    }
    else
    {
        BlockSizeSkips = (encrypter.LegacyBlockSize.MaxSize - encrypter.LegacyBlockSize.MinSize) /
                         encrypter.LegacyBlockSize.SkipSize;
        for (int i = 0; i < BlockSizeSkips + 1; i++)
        {
            Console.WriteLine(
                $"{i + 1}: {encrypter.LegacyBlockSize.MinSize + (i * encrypter.LegacyBlockSize.SkipSize)}");
        }
    }

    Console.Write("Block size: ");
    int blockSize = ValidateInputInt(1, BlockSizeSkips);

    encrypter.BlockSize = encrypter.LegacyBlockSize.MinSize + (blockSize * encrypter.LegacyBlockSize.SkipSize);


    // Write a message to encrypt
    Console.WriteLine();
    Console.Write("Enter a message to encrypt: ");
    string message = File.ReadAllText("C:\\Users\\gummi\\Desktop\\test.txt");

    Console.WriteLine();
    byte[] encrypted = encrypter.Encrypt(message);
    //Console.WriteLine($"Encrypted message: {Convert.ToBase64String(encrypted)}");

    string decrypted = encrypter.Decrypt(encrypted);
    //Console.WriteLine($"Decrypted message: {decrypted}");
    Console.WriteLine($"Encrypted time: {encrypter.TimeSpans[0].Milliseconds} ms");
    Console.WriteLine($"Decrypted time: {encrypter.TimeSpans[1].Milliseconds} ms");

    Console.WriteLine("--- End ---");

    Console.WriteLine();
    Console.WriteLine("Try again? (y/n)");
    string input = Console.ReadLine();
    if (input.ToLower() == "y")
    {
        power = true;
    }
    else
    {
        power = false;
    }
} while (power);


static int ValidateInputInt(int min, int max)
{
    int input = 0;
    bool valid = false;

    while (!valid)
    {
        try
        {
            input = int.Parse(Console.ReadLine());
            if (input < min || input > max)
            {
                Console.WriteLine($"Please enter a number between {min} and {max}");
            }
            else
            {
                valid = true;
            }
        }
        catch (Exception)
        {
            Console.WriteLine($"Please enter a number between {min} and {max}");
        }
    }

    return input;
}