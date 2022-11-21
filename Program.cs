using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using JWT;
using JWT.Serializers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace QRCodeGenerator
{
    class Program
    {
        public static void Main()
        {
            try
            {
                Console.WriteLine("Testing...");
                //---------------------------------------------------------------------
                //inputs include campaignname, end date of campaign and key identifier
                //---------------------------------------------------------------------
                string campaignName = "D1000_21NOV2022";DateTime currentTime = new DateTime(2022, 11, 21); int iKey = 1; //0 = CAMPAIGN_1, 1 = CAMPAIGN_2

                string[] keyIds = new string[] { "CAMPAIGN_1", "CAMPAIGN_2" };
                string[] secrets = new string[] { "84jdhk69-7484-8d75-9d84-03hdby84os64", "036fk79u-8gjg-dh57-d875-03hdby84os64" };
                string[] machines = new string[] { "90000002", "90000003" };
                int[] sites = new int[] { 90000050, 90000300 };


                string keyId = keyIds[iKey];//0=CAMPAIGN_1, 1=CAMPAIGN_2
                string secret = secrets[iKey];
                string machine = machines[iKey];
                int site = sites[iKey];
                currentTime = currentTime.AddMinutes(3);

                int minCount = 1;
                int maxCount = 1000;

                string pathTop = "/Users/cengamat/Projects/git-cengamat/qrcodegenerator/qrcode/";

                FileStream fileStream = null;
                int nxtFile = 0;
                for (int nxt = minCount; nxt <= maxCount; nxt++)//iterate qrcodes to generate
                {
                    int fileIndex = 1 + ((nxt-1) / 100);//iterate set of qrcodes to generate per file

                    if (fileIndex > nxtFile) //cross file size threshold, or create first file
                    {
                        if (fileStream != null) fileStream.Dispose();//dispose of old file resources
                        fileStream = new FileStream(pathTop + keyId + "_" +campaignName + "_" + fileIndex.ToString("00") + ".csv", FileMode.Create);//create a new file
                        WriteToFile("fileName", "qrcode", fileStream);//header
                        nxtFile = fileIndex;
                    }

                    //json template... will overwrite modifiable fields
                    string strLoyalty = @"{
                    'machineNo': '90000002',
                    'siteId': 90000050,
                    'keyId' : 'XXXXXX',
                    'amount': 0,
                    'currency': 'GBP',
                    'timestamp': '2020-01-06T10:00:00'
                    }";

                    JObject jsonLoyalty = JObject.Parse(strLoyalty);

                    string name = campaignName + "_" + nxt.ToString("0000000");

                    jsonLoyalty["timestamp"] = currentTime.ToString("s");
                    jsonLoyalty["keyId"] = keyId;
                    jsonLoyalty["machineNo"] = machine;
                    jsonLoyalty["siteId"] = site;

                    CreateQRCode(name, secret, jsonLoyalty, true, fileStream);//campaignName,private secret,payload, writeToFile t/f, destination file stream
                }

                while (true)
                {
                    Console.ReadKey();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }
        }

        public static void CreateQRCode(string name, string strSecret, JObject jsonLoyalty, bool bCreate = true, FileStream fileStream=null)
        {
            Console.WriteLine("Testing...");


            byte[] secret = Encoding.UTF8.GetBytes(strSecret);

            string strSecret2 = "cengoxsecret";//to sign the outer layer jwt to be checked by apps team... public secret
            byte[] secret2 = Encoding.UTF8.GetBytes(strSecret2);


            //Generate and assign guid
            Guid guid = Guid.NewGuid();//random guid
            Console.WriteLine("GUID: >{0}<", guid.ToString());

            //WITH GUID
            jsonLoyalty["guid"] = guid.ToString();


            //Display the original data
            Console.WriteLine("Loyalty: >{0}<", JsonConvert.SerializeObject(jsonLoyalty, Formatting.Indented));

            string justJson = JsonConvert.SerializeObject(jsonLoyalty, Formatting.None);

            string jwt = CreateJWT(jsonLoyalty, strSecret);//create loyalty jwt

            byte[] hash2 = SignString(secret2, jwt);
            string prependedJwt = Convert.ToBase64String(hash2) + "." + jwt;


            if (bCreate)
                WriteToFile(name, prependedJwt, fileStream);//write qrcode payload to csv file


            bool bOk = false;

           string result = VeryifyAndExtractTheJWT(prependedJwt, strSecret2, out bOk);//unwrap inner jwt from the envelope
            Console.WriteLine("ExtractedJWT: Len:{1}, OK?: {2}, >{0}<", result, result.Length, bOk ? "true" : "false");


            bOk = CheckJWT(result, strSecret);
            Console.WriteLine("CheckFrom.Net on JWT: OK?:{0}", bOk ? "true" : "false");


            result = VeryifyAndExtractFromJWT(result, strSecret, out bOk);//unwrap message from jwt

            JObject extractedLoyaltyJson = JObject.Parse(result);

            Console.WriteLine("ExtractedLoyalty: Len:{1}, OK?: {2}, >{0}<", JsonConvert.SerializeObject(extractedLoyaltyJson, Formatting.Indented), result.Length, bOk ? "true" : "false");

        }

        public static string VeryifyAndExtractTheJWT(string jwt, string strSecret, out bool bResult)
        {
            byte[] secret = Encoding.UTF8.GetBytes(strSecret);

            // Decrypt the bytes to a string.
            string[] data = jwt.Split('.');
            string payload = data[1] + "." + data[2] + "." + data[3];
            string hash = data[0];
            byte[] readHash = System.Convert.FromBase64String(hash);
            Console.WriteLine("StrippedPayload: Len:{1}, >{0}<", payload, payload.Length);

            bResult = CheckString(secret, readHash, payload);
            Console.WriteLine("Verification: >{0}<", bResult == true ? "Hash Verified" : "HashFailed!");
            return payload;
        }

        public static string VeryifyAndExtractFromJWT(string jwt, string strSecret, out bool bResult)
        {
            string decrypted = "";
            byte[] secret = Encoding.UTF8.GetBytes(strSecret);

            // Decrypt the bytes to a string.
            string[] encryptedJWT = jwt.Split('.');
            string encryptedPayload = encryptedJWT[0] + "." + encryptedJWT[1];
            string hashFromJWT = encryptedJWT[2];
            byte[] readHash = System.Convert.FromBase64String(hashFromJWT);
            Console.WriteLine("EncryptedPayload: Len:{1}, >{0}<", encryptedPayload, encryptedPayload.Length);

            string decryptedPayload = Base64Decode(encryptedJWT[1]);
            decrypted = Base64Decode(encryptedJWT[0]) + '.' + decryptedPayload + '.' + Base64Decode(encryptedJWT[2]);

            //Display the decrypted data
            Console.WriteLine("Decrypted: Len:{1}, >{0}<", decrypted, decrypted.Length);
            bResult = CheckString(secret, readHash, encryptedPayload);
            Console.WriteLine("Verification: >{0}<", bResult == true ? "Hash Verified" : "HashFailed!");
            return decryptedPayload;
        }

        public static string CreateJWT(JObject json, string strSecret, bool bHeader = true)
        {
            Console.WriteLine("JSON: >{0}<", JsonConvert.SerializeObject(json, Formatting.Indented));
            string payload = JsonConvert.SerializeObject(json, Formatting.None);
            return CreateJWT(payload, strSecret, bHeader);
        }

        public static string CreateJWT(string payload, string strSecret, bool bHeader = true)
        {
            string jwt = "";
            try
            {
                string strHeader = @"{
                    'alg': 'HS256',
                    'typ': 'JWT'
                }";
                byte[] secret = Encoding.UTF8.GetBytes(strSecret);

                JObject jsonHeader = JObject.Parse(strHeader);


                // Encrypt the string to an array of bytes.
                string encryptedHeader = Base64Encode(JsonConvert.SerializeObject(jsonHeader, Formatting.None));
                string encrypted = Base64Encode(payload);

                string jwtPayload = (bHeader ? encryptedHeader + "." : "") + encrypted;
                byte[] hash = SignString(secret, jwtPayload);
                Console.WriteLine("Hash: Len:{1}, >{0}<", Convert.ToBase64String(hash), hash.Length);

                jwt = jwtPayload + "." + Convert.ToBase64String(hash);
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }
            return jwt;
        }

        public static bool CheckJWT(string token, string secret)
        {
            bool bOk = false;
            try
            {
                IJsonSerializer serializer = new JsonNetSerializer();
                IDateTimeProvider provider = new UtcDateTimeProvider();
                IJwtValidator validator = new JwtValidator(serializer, provider);
                IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
                IJwtDecoder decoder = new JwtDecoder(serializer, urlEncoder);

                string json = decoder.Decode(token, secret, verify: false);
                Console.WriteLine(json);
                bOk = true;
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }
            //catch (TokenExpiredException)
            //{
            //    Console.WriteLine("Token has expired");
            //}
            //catch (SignatureVerificationException)
            //{
            //    Console.WriteLine("Token has invalid signature");
            //}
            return bOk;
        }

        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        public static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

        public static byte[] SignString(byte[] key, String source)
        {
            byte[] hashValue = null;
            // Initialize the keyed hash object.
            using (HMACSHA256 hmac = new HMACSHA256(key))
            {

                var bytes = System.Text.Encoding.UTF8.GetBytes(source);
                hashValue = hmac.ComputeHash(bytes);
            }
            return hashValue;
        } // end SignFile

        public static bool CheckString(byte[] key, byte[] hash, String source)
        {
            bool err = false;
            // Initialize the keyed hash object.
            using (HMACSHA256 hmac = new HMACSHA256(key))
            {
                // Create a FileStream for the source file.
                var bytes = System.Text.Encoding.UTF8.GetBytes(source);
                byte[] computedHash = hmac.ComputeHash(bytes);
                // compare the computed hash with the stored value

                for (int i = 0; i < hash.Length; i++)
                {
                    if (computedHash[i] != hash[i])
                    {
                        err = true;
                    }
                }
            }
            if (err)
            {
                Console.WriteLine("Hash values differ! Signed string has been tampered with!");
                return false;
            }
            else
            {
                Console.WriteLine("Hash values agree -- no tampering occurred.");
                return true;
            }

        } //end VerifyFile

        public static void WriteToFile(string fileName, string qrcode, FileStream stream)
        {
            //(System.IO.Stream stream, System.Text.Encoding? encoding = default, int bufferSize = -1, bool leaveOpen = false);
            using (StreamWriter writer = new StreamWriter(stream, System.Text.Encoding.ASCII, 2048,true))
            {
                writer.WriteLine(fileName + "," + qrcode);

                //writer.Close();
            }
        }
    }
}
