using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.IO;

namespace EncryptedSha256
{
    public partial class Form1 : Form
    {
        
        public Form1()
        {
            InitializeComponent();
        }
        
        
        private void btnKaydet_Click(object sender, EventArgs e)
        {
            string password = "1234";
            string encripted= EncryptString(txtPassword.Text, password, true);
            

           
            string Connect = @"Data Source=DESKTOP-A527NHG\SQLEXPRESS;Initial Catalog=DenemeTable;User ID=sa;Password=as";
            using (var sqlcon=new SqlConnection(Connect))
            {
                try
                {
                    sqlcon.Open();
                    SqlCommand cmd = new SqlCommand("Insert INTO LoginEncrypt(LogName,LogPassword) VALUES('" + txtName.Text+ "','" + encripted+ "')", sqlcon);
                    cmd.ExecuteNonQuery();
                    sqlcon.Close();
                    MessageBox.Show($"Execution is done\n {encripted} ","Status", MessageBoxButtons.OK, MessageBoxIcon.Warning);

                }
                catch(Exception ex)
                {
                    MessageBox.Show(ex.Message);
                }
               
            }
        }

        public static string EncryptString(string text, string password, bool compressText)
        {
            byte[] baPwd = Encoding.UTF8.GetBytes(password);

            // Hash the password with SHA256
            byte[] baPwdHash = SHA256Managed.Create().ComputeHash(baPwd);

            byte[] baText = Encoding.UTF8.GetBytes(text);

            if (compressText)
                baText = Compressor.Compress(baText);

            byte[] baSalt = GetRandomBytes();
            byte[] baEncrypted = new byte[baSalt.Length + baText.Length];

            // Combine Salt + Text
            for (int i = 0; i < baSalt.Length; i++)
                baEncrypted[i] = baSalt[i];
            for (int i = 0; i < baText.Length; i++)
                baEncrypted[i + baSalt.Length] = baText[i];

            baEncrypted = AES_Encrypt(baEncrypted, baPwdHash);

            string result = Convert.ToBase64String(baEncrypted);
            return result;
        }

        public static string DecryptString(string text, string password, bool decompressText)
        {
            byte[] baPwd = Encoding.UTF8.GetBytes(password);

            // Hash the password with SHA256
            byte[] baPwdHash = SHA256Managed.Create().ComputeHash(baPwd);

            byte[] baText = Convert.FromBase64String(text);

            byte[] baDecrypted = AES_Decrypt(baText, baPwdHash);

            // Remove salt
            int saltLength = GetSaltLength();
            byte[] baResult = new byte[baDecrypted.Length - saltLength];
            for (int i = 0; i < baResult.Length; i++)
                baResult[i] = baDecrypted[i + saltLength];

            if (decompressText)
                baResult = Compressor.Decompress(baResult);

            string result = Encoding.UTF8.GetString(baResult);
            return result;
        }

        public static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }

        public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }

        public static byte[] GetRandomBytes()
        {
            int saltLength = GetSaltLength();
            byte[] ba = new byte[saltLength];
            RNGCryptoServiceProvider.Create().GetBytes(ba);
            return ba;
        }

        public static int GetSaltLength()
        {
            return 8;
        }

        private void btnGoster_Click(object sender, EventArgs e)
        {
            string password = "1234";
           // string encripted = DecryptString(txtPassword.Text, password, true);
            string Connect = @"Data Source=DESKTOP-A527NHG\SQLEXPRESS;Initial Catalog=DenemeTable;User ID=sa;Password=as";
            using (var sqlcon = new SqlConnection(Connect))
            {
                try
                {
                    sqlcon.Open();
                    SqlCommand cmd = new SqlCommand("SELECT LogPassword FROM LoginEncrypt LogPassword where Id=6", sqlcon);
                    SqlDataReader sqlDataReader = cmd.ExecuteReader();
                    while (sqlDataReader.Read())
                    {
                        string Pswdstr= sqlDataReader.GetValue(0).ToString();
                        txtName.Text = Pswdstr;
                        txtPassword.Text = DecryptString(Pswdstr, password, true);
                    }
                    sqlDataReader.Close();
                    cmd.Dispose();
                    sqlcon.Close();
                    MessageBox.Show($"Execution is done\n {txtPassword.Text} ", "Status", MessageBoxButtons.OK, MessageBoxIcon.Warning);

                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message);
                }

            }
        }
    }
}
