using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ProSoft.Crypto.Aes
{
    public static class Encryption
    {
        #region Encrypt/Decrypt

        public static string Decrypt(string encryptedString, string aesKey)
        {
            byte[] decryptedAuthTokenAsBytes = AesDecrypt(FromBase64String(encryptedString), aesKey);
            return Encoding.UTF8.GetString(decryptedAuthTokenAsBytes);
        }

        public static string Encrypt(string plainTextString, string aesKey)
        {
            return ToBase64String(AesEncrypt(plainTextString, aesKey));
        }

        #endregion


        #region Key/Random String Generators

        private static byte[] CreateKey(string password)
        {
            var salt = new byte[] { 1, 2, 23, 234, 37, 48, 134, 63, 248, 4 };

            const int Iterations = 9872;
            using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, Iterations))
                return rfc2898DeriveBytes.GetBytes(32);
        }

        public static string CreateAesKeyFromUserPassword(string password)
        {
            byte[] passwordByteArray = CreateKey(password);

            var aesEncryption = new RijndaelManaged
            {
                KeySize = 256,
                BlockSize = 128,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7,
                Key = passwordByteArray
            };

            aesEncryption.GenerateIV();
            string ivStr = Convert.ToBase64String(aesEncryption.IV);
            string keyStr = Convert.ToBase64String(aesEncryption.Key);

            string completeKey = ivStr + "," + keyStr;

            return Convert.ToBase64String(Encoding.UTF8.GetBytes(completeKey));
        }

        public static string CreateRandomString(int stringLength = 32, bool strongPassword = true, bool lowercaseOnly = false)
        {
            const string specialCharacters = @"!#$&()+=?[]_";

            var allowedChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ0123456789";

            var random = new Random();
            int seed = random.Next(1, int.MaxValue);

            if (lowercaseOnly)
                allowedChars = "abcdefghijkmnopqrstuvwxyz0123456789";

            var chars = new char[stringLength];
            var rnd = new Random(seed);

            for (var i = 0; i < stringLength; i++)
            {
                // if using special characters...
                if (strongPassword && i % random.Next(3, stringLength) == 0)
                    chars[i] = specialCharacters[rnd.Next(0, specialCharacters.Length)];
                else
                    chars[i] = allowedChars[rnd.Next(0, allowedChars.Length)];
            }

            return new string(chars);
        }

        #endregion


        #region AES Engine

        private static byte[] AesEncrypt(string plainText, string aesKey)
        {
            string[] aesKeyParams = Encoding.UTF8.GetString(FromBase64String(aesKey)).Split(',');
            byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(plainText);
            byte[] encryptedBytes;
            byte[] saltBytes = Encoding.UTF8.GetBytes(aesKeyParams[0]);

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged aes = new RijndaelManaged())
                {
                    aes.KeySize = 256;
                    aes.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(aesKeyParams[1]), saltBytes, 1000);
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.IV = key.GetBytes(aes.BlockSize / 8);

                    aes.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }

        private static byte[] AesDecrypt(byte[] bytesToBeDecrypted, string aesKey)
        {
            string[] aesKeyParams = Encoding.UTF8.GetString(FromBase64String(aesKey)).Split(',');
            byte[] decryptedBytes;
            byte[] saltBytes = Encoding.UTF8.GetBytes(aesKeyParams[0]);

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged aes = new RijndaelManaged())
                {
                    aes.KeySize = 256;
                    aes.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(aesKeyParams[1]), saltBytes, 1000);
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.IV = key.GetBytes(aes.BlockSize / 8);

                    aes.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }

        #endregion


        #region Base 64 Converters

        private static string ToBase64String(byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }

        private static byte[] FromBase64String(string base64EncodedData)
        {
            return Convert.FromBase64String(base64EncodedData);
        }

        #endregion
    }
}

