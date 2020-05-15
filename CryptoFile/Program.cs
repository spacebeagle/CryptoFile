using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptoFile
{
    class Program
    {
        static string input;
        static string output;
        static string password;
        static bool decrypt;

        static int Main(string[] args)
        {

            var parser = new ArgsParser(args);
            int argCount = 0;
            if (!string.IsNullOrEmpty(input = parser.GetValue("input")))
            {
                argCount += 2;
            }
            if (!string.IsNullOrEmpty(output = parser.GetValue("output")))
            {
                argCount += 2;
            }
            if (!string.IsNullOrEmpty(password = parser.GetValue("password")))
            {
                argCount += 2;
            }
            if ((decrypt = parser.GetFlag("decrypt")))
            {
                argCount += 1;
            }
            string name = parser.LastValue();
            if (string.IsNullOrEmpty(input) && string.IsNullOrEmpty(output))
            {
                if (argCount >= args.Length || string.IsNullOrEmpty(name))
                {
                    return -1;
                }
                argCount++;
                if (name.EndsWith(".crypto"))
                {
                    if (decrypt)
                    {
                        input = name;
                        output = input.Substring(0, input.Length - 7);
                    }
                    else
                    {
                        output = name;
                        input = output.Substring(0, input.Length - 7);
                    }
                }
                else
                {
                    if (decrypt)
                    {
                        input = name + ".crypto";
                        output = name;
                    }
                    else
                    {
                        output = name;
                        input = name + ".crypto";
                    }
                }
            }
            else if (string.IsNullOrEmpty(input))
            {
                if (argCount >= args.Length || string.IsNullOrEmpty(name))
                {
                    if (output.EndsWith(".crypto"))
                    {
                        if (decrypt)
                        {
                            Console.WriteLine("入力ファイルが正しく指定されていません");
                            return -1;
                        }
                        else
                        {
                            input = output.Substring(0, input.Length - 7);
                        }
                    }
                }
                else
                {
                    argCount++;
                    input = name;
                }
            }
            else if (string.IsNullOrEmpty(output))
            {
                if (argCount >= args.Length || string.IsNullOrEmpty(name))
                {
                    if (input.EndsWith(".crypto"))
                    {
                        if (decrypt)
                        {
                            output = input.Substring(0, input.Length - 7);
                        }
                        else
                        {
                            Console.WriteLine("出力ファイルが正しく指定されていません");
                            return -1;
                        }
                    }
                }
                else
                {
                    argCount++;
                    output = name;
                }
            }
            if (!File.Exists(input))
            {
                Console.WriteLine("入力ファイルが存在していません");
                return -1;
            }
            if (File.Exists(output))
            {
                Console.WriteLine("出力ファイルがすでに存在しています");
                return -1;
            }
            if (string.IsNullOrEmpty(password))
            {
                if (decrypt)
                {
                    Console.WriteLine("パスワードが指定されていません");
                    return -1;
                }
                RandomNumberGenerator rng = RandomNumberGenerator.Create();
                byte[] rand = new byte[8];
                rng.GetBytes(rand);
                password = Convert.ToBase64String(rand);
                Console.WriteLine("new key string=" + password);
            }

            Console.WriteLine("input=" + input);
            Console.WriteLine("output=" + output);
            if(decrypt)
            {
                if (FileDecrypt(input, output, password))
                    return 0;
            }
            else
            {
                if (FileEncrypt(input, output, password))
                    return 0;
            }
            return -1;
        }

        static private bool FileEncrypt(string FilePath,string OutFilePath,string Password)
        {
            //Stopwatchオブジェクトを作成する
            System.Diagnostics.Stopwatch sw = new System.Diagnostics.Stopwatch();
            //ストップウォッチを開始する
            sw.Start();

            int len;
            byte[] buffer = new byte[4096];

            using (FileStream outfs = new FileStream(OutFilePath, FileMode.Create, FileAccess.Write))
            {
                using (AesManaged aes = new AesManaged())
                {
                    aes.BlockSize = 128;              // BlockSize = 16bytes
                    aes.KeySize = 128;                // KeySize = 16bytes
                    aes.Mode = CipherMode.CBC;        // CBC mode
                    aes.Padding = PaddingMode.PKCS7;    // Padding mode is "PKCS7".

                    //入力されたパスワードをベースに擬似乱数を新たに生成
                    Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes(Password, 16);
                    byte[] salt = new byte[16]; // Rfc2898DeriveBytesが内部生成したソルトを取得
                    salt = deriveBytes.Salt;
                    // 生成した擬似乱数から16バイト切り出したデータをパスワードにする
                    byte[] bufferKey = deriveBytes.GetBytes(16);

                    aes.Key = bufferKey;
                    // IV ( Initilization Vector ) は、AesManagedにつくらせる
                    aes.GenerateIV();

                    //Encryption interface.
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (CryptoStream cse = new CryptoStream(outfs, encryptor, CryptoStreamMode.Write))
                    {
                        outfs.Write(salt, 0, 16);     // salt をファイル先頭に埋め込む
                        outfs.Write(aes.IV, 0, 16); // 次にIVもファイルに埋め込む
                        using (FileStream fs = new FileStream(FilePath, FileMode.Open, FileAccess.Read))
                        {
                            while ((len = fs.Read(buffer, 0, 4096)) > 0)
                            {
                                cse.Write(buffer, 0, len);
                            }
                        }

                    }

                }
            }
            //ストップウォッチを止める
            sw.Stop();

            //結果を表示する
            long resultTime = sw.ElapsedMilliseconds;

            //Encryption succeed.
            Console.WriteLine("暗号化成功: " + Path.GetFileName(OutFilePath) + Environment.NewLine);
            Console.WriteLine("実行時間: " + resultTime.ToString() + "ms");

            return (true);
        }

        static private bool FileDecrypt(string FilePath, string OutFilePath, string Password)
        {
            int len;
            byte[] buffer = new byte[4096];

            using (FileStream outfs = new FileStream(OutFilePath, FileMode.Create, FileAccess.Write))
            {
                using (FileStream fs = new FileStream(FilePath, FileMode.Open, FileAccess.Read))
                {
                    using (AesManaged aes = new AesManaged())
                    {
                        aes.BlockSize = 128;              // BlockSize = 16bytes
                        aes.KeySize = 128;                // KeySize = 16bytes
                        aes.Mode = CipherMode.CBC;        // CBC mode
                        aes.Padding = PaddingMode.PKCS7;    // Padding mode is "PKCS7".

                        // salt
                        byte[] salt = new byte[16];
                        fs.Read(salt, 0, 16);

                        // Initilization Vector
                        byte[] iv = new byte[16];
                        fs.Read(iv, 0, 16);
                        aes.IV = iv;

                        // ivをsaltにしてパスワードを擬似乱数に変換
                        Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes(Password, salt);
                        byte[] bufferKey = deriveBytes.GetBytes(16);    // 16バイトのsaltを切り出してパスワードに変換
                        aes.Key = bufferKey;

                        //Decryption interface.
                        ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                        using (CryptoStream cse = new CryptoStream(fs, decryptor, CryptoStreamMode.Read))
                        {
                            while ((len = cse.Read(buffer, 0, 4096)) > 0)
                            {
                                outfs.Write(buffer, 0, len);
                            }
                        }
                    }
                }
            }
            //Decryption succeed.
            Console.WriteLine("復号成功: " + Path.GetFileName(OutFilePath));
            return (true);
        }
    }


    class ArgsParser
    {
        string[] args;
        public ArgsParser(string[] argStrings)
        {
            args = argStrings;
        }

        int GetCommand(string command)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (IsCommand(i))
                {
                    string arg = args[i].ToLower();
                    if (arg.EndsWith(command))
                    {
                        return i;
                    }
                    string sCommand = command.Substring(0, 1);
                    if (IsCommand(command))
                    {
                        sCommand = command.Substring(0, 2);
                    }
                    if (arg.EndsWith(sCommand))
                    {
                        return i;
                    }
                }
            }
            return -1;
        }

        public string LastValue()
        {
            int idx = args.Length - 1;
            if (idx>=0 && !IsCommand(idx))
            {
                return args[idx];
            }
            return null;
        }

        public string GetValue(string command)
        {
            int idx = GetCommand(command);
            if (idx < args.Length-1 && !IsCommand(idx + 1))
            {
                return args[idx + 1];
            }
            return null;
        }

        public int GetInt(string command)
        {
            string v = GetValue(command);
            int num;
            if(!string.IsNullOrEmpty(v) & int.TryParse(v,out num))
            {
                return num;
            }
            return -1;
        }

        public bool GetFlag(string command)
        {
            if (GetCommand(command) >= 0)
                return true;
            return false;
        }

        public bool IsCommand(string arg)
        {
            return arg.StartsWith("-");
        }

        public bool IsCommand(int idx)
        {
            if (idx >= args.Length)
                return false;
            return args[idx].StartsWith("-");
        }
    }
}
