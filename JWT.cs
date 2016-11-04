using System;
using System.Text;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace JWT {
    /// <summary>
    /// Token class
    /// </summary>
    public static class JWTToken {
        
        private static DateTime _utc0 = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Generate a new token. Throws ArgumentOutOfRangeException if expirationTimeInMinutes is <= 0
        /// </summary>
        /// <param name="parameters">Provide key value information that you want to store in this token</param>
        /// <param name="expirationTimeInMinutes">Provide the expiration time of token</param>
        /// <returns>Returns the generated token</returns>
        public static string New(Dictionary<string, string> parameters, int expirationTimeInMinutes) {
            if (expirationTimeInMinutes <= 0) {
                throw new ArgumentOutOfRangeException();
            }
            var header = new Dictionary<string, string>() { 
                {"alg", "HMAC"},
                {"typ", "JWT"}
            };
            string headerSerialized = _serialize(header);
            string headerEncoded = _convertToUrlFriendlyBase64(headerSerialized);
            double exp = DateTime.Now.AddMinutes(expirationTimeInMinutes).Subtract(_utc0).TotalSeconds;
            parameters.Add("exp", exp.ToString());
            string tokenInfoSerialized = _serialize(parameters);
            string tokenInfoEncoded = _convertToUrlFriendlyBase64(tokenInfoSerialized);
            string signature = _encrypt(String.Format("{0}.{1}", headerEncoded, tokenInfoEncoded));
            return String.Format("{0}.{1}.{2}", headerEncoded, tokenInfoEncoded, signature);
        }

        /// <summary>
        /// Parse token
        /// </summary>
        /// <returns>Information stored in token</returns>
        public static ParsingInfo Parse(string token) {
            bool _isValid = false;
            bool _hasExpired = true;
            double _expiredByInSec = 0;
            Dictionary<string, string> _content = new Dictionary<string, string>();

            if (!_isTokenValid(token)) {
                _isValid = false;
            } else {
                _isValid = true;
                if (_hasTokenExpired(token)) {
                    _hasExpired = true;
                    _expiredByInSec = _tokenExpiredByInSec(token);
                } else {
                    _hasExpired = false;
                    _content = _getTokenInfo(token);
                }
            }
            return new ParsingInfo {
                IsValid = _isValid,
                HasExpired = _hasExpired,
                ExpiredByInSec = _expiredByInSec,
                Content = _content
            };
        }

        private static string _encrypt(string text) {
            string salt = "twejjj1231jkk53kldfsnjj53jk22poouvc59a0aw88rtytsfv1weligvnmj0ist";
            using (HMACSHA256 hmacSha256 = new HMACSHA256(Encoding.UTF8.GetBytes(salt))) {
                byte[] saltedHash = hmacSha256.ComputeHash(Encoding.UTF8.GetBytes(text));
                string base64Text = Convert.ToBase64String(saltedHash);
                return base64Text.Replace('+', '-').Replace('/', '_').Replace("=", String.Empty);
            }
        }

        private static string _serialize(Object o) {
            return JsonConvert.SerializeObject(o);
        }

        private static Dictionary<string, string> _deserialize(string serializedString) {
            return JsonConvert.DeserializeObject<Dictionary<string, string>>(serializedString);
        }

        private static string _convertToUrlFriendlyBase64(string text) {
            string base64Text = Convert.ToBase64String(Encoding.UTF8.GetBytes(text));
            return base64Text.Replace('+', '-').Replace('/', '_').Replace("=", String.Empty);
        }

        private static string _decodeUrlFriendlyBase64(string encodedText) {
            string base64Text = encodedText.Replace('-', '+').Replace('_', '/');
            base64Text = base64Text.PadRight(base64Text.Length + (4 - base64Text.Length % 4) % 4, '=');
            byte[] data = Convert.FromBase64String(base64Text);
            return Encoding.UTF8.GetString(data);
        }

        private static bool _isTokenValid(string token) {
            if (String.IsNullOrEmpty(token)) {
                return false;
            }
            string[] parts;
            try {
                parts = token.Split('.');
            } catch (Exception) {
                return false;
            }
            if (parts != null && parts.Length != 3) {
                return false;
            }
            if (_encrypt(String.Format("{0}.{1}", parts[0], parts[1])) != parts[2]) {
                return false;
            }
            return true;
        }

        private static bool _hasTokenExpired(string token) {
            string[] parts = token.Split('.');
            Dictionary<string, string> parameters = _deserialize(_decodeUrlFriendlyBase64(parts[1]));
            double expirationTime = Convert.ToDouble(parameters["exp"]);
            double iat = DateTime.Now.Subtract(_utc0).TotalSeconds;
            if (expirationTime < iat) {
                return true;
            }
            return false;
        }

        private static double _tokenExpiredByInSec(string token) {
            string[] parts = token.Split('.');
            Dictionary<string, string> parameters = _deserialize(_decodeUrlFriendlyBase64(parts[1]));
            double expirationTime = Convert.ToDouble(parameters["exp"]);
            double iat = DateTime.Now.Subtract(_utc0).TotalSeconds;
            return iat - expirationTime;
        }

        private static Dictionary<string, string> _getTokenInfo(string token) {
            string[] parts = token.Split('.');
            Dictionary<string, string> parameters = _deserialize(_decodeUrlFriendlyBase64(parts[1]));
            parameters.Remove("exp");
            return parameters;
        }

    }

    /// <summary>
    /// Holds token information
    /// </summary>
    public class ParsingInfo {
        public bool IsValid { get; set; }
        public bool HasExpired { get; set; }
        public double ExpiredByInSec { get; set; }
        public Dictionary<string, string> Content { get; set; }
    }

}
