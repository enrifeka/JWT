using System;
using System.Text;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace JWT {

    public class BasicToken {

        private string _token;

        /// <summary>
        /// Set the token you want to verify 
        /// </summary>
        public string Value { set { _token = value; } }

        private DateTime _utc0 = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        private DateTime _issueTime = DateTime.Now;

        /// <summary>
        /// You can provide the expiration time of the token. Time can not be negative
        /// </summary>
        public BasicToken() {
            
        }

        /// <summary>
        /// You can provide the token and the expiration time. Time can not be negative
        /// </summary>
        /// <param name="token">Set the token you want to validate</param>
        public BasicToken(string token) {
            this._token = token;
        }

        /// <summary>
        /// Generate a new token. The token member of this class is not set to the new generated token
        /// </summary>
        /// <param name="parameters">Provide key value information that you want to store in this token</param>
        /// <returns>Returns the generated token</returns>
        public string GenerateToken(Dictionary<string, string> parameters, int expirationTimeInMinutes) {
            if (expirationTimeInMinutes < 0) {
                throw new Exception("Expiration time cannot be negative");
            }
            var header = new Dictionary<string, string>() { 
                {"alg", "HMAC"},
                {"typ", "JWT"}
            };
            string headerSerialized = _serialize(header);
            string headerEncoded = _convertToUrlFriendlyBase64(headerSerialized);
            double exp = _issueTime.AddMinutes(expirationTimeInMinutes).Subtract(_utc0).TotalSeconds;
            parameters.Add("exp", exp.ToString());
            string tokenInfoSerialized = _serialize(parameters);
            string tokenInfoEncoded = _convertToUrlFriendlyBase64(tokenInfoSerialized);
            string signature = _encrypt(String.Format("{0}.{1}", headerEncoded, tokenInfoEncoded));
            return String.Format("{0}.{1}.{2}", headerEncoded, tokenInfoEncoded, signature);
        }

        /// <summary>
        /// Verify if the token has the standart format, is signed and not changed. Throws an exception if the Token class member is empty
        /// </summary>
        /// <returns></returns>
        public bool IsValid() {
            if (String.IsNullOrEmpty(_token)) {
                throw new ArgumentNullException("Provide a token to validate");
            }
            string[] parts;
            try {
                parts = _token.Split('.');
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

        /// <summary>
        /// Check if the token has expired. Throws an exception if the token is not valid
        /// </summary>
        /// <returns></returns>
        public bool HasExpired() {
            if (!IsValid()) {
                throw new TokenIsNotValidException();
            }
            string[] parts = _token.Split('.');
            var parameters = _deserialize(_decodeUrlFriendlyBase64(parts[1]));
            double expirationTime = Convert.ToDouble(parameters["exp"]);
            double iat = _issueTime.Subtract(_utc0).TotalSeconds;
            if (expirationTime < iat) {
                return true;
            }
            return false;
        }

        /// <summary>
        /// Check the time since the token has expired. Throws an exception if the token is not valid or has not expired
        /// </summary>
        /// <returns>The time in seconds since the token has expired</returns>
        public double ExpiredByInSec() {
            if (!HasExpired()) {
                throw new TokenHasNotExpiredException();
            }
            string[] parts = _token.Split('.');
            Dictionary<string, string> parameters = _deserialize(_decodeUrlFriendlyBase64(parts[1]));
            double expirationTime = Convert.ToDouble(parameters["exp"]);
            double iat = _issueTime.Subtract(_utc0).TotalSeconds;
            return iat - expirationTime;
        }

        /// <summary>
        /// Get the information stored in token. Throws an exception if the token has expired or is not valid
        /// </summary>
        /// <returns>Information in key value format</returns>
        public Dictionary<string, string> GetTokenInfo() {
            if (HasExpired()) {
                throw new TokenHasExpiredException();
            }
            string[] parts = _token.Split('.');
            var parameters = _deserialize(_decodeUrlFriendlyBase64(parts[1]));
            parameters.Remove("exp");
            return parameters;
        }

        private string _encrypt(string text) {
            string salt = "twejjj1231jkk53kldfsnjj53jk22poouvc59a0aw88rtytsfv1weligvnmj0ist";
            using (HMACSHA256 hmacSha256 = new HMACSHA256(Encoding.UTF8.GetBytes(salt))) {
                byte[] saltedHash = hmacSha256.ComputeHash(Encoding.UTF8.GetBytes(text));
                string base64Text = Convert.ToBase64String(saltedHash);
                return base64Text.Replace('+', '-').Replace('/', '_').Replace("=", String.Empty);
            }
        }

        private string _serialize(Object o) {
            return JsonConvert.SerializeObject(o);
        }

        private Dictionary<string, string> _deserialize(string serializedString) {
            return JsonConvert.DeserializeObject<Dictionary<string, string>>(serializedString);
        }

        private string _convertToUrlFriendlyBase64(string text) {
            string base64Text = Convert.ToBase64String(Encoding.UTF8.GetBytes(text));
            return base64Text.Replace('+', '-').Replace('/', '_').Replace("=", String.Empty);
        }

        private string _decodeUrlFriendlyBase64(string encodedText) {
            string base64Text = encodedText.Replace('-', '+').Replace('_', '/');
            base64Text = base64Text.PadRight(base64Text.Length + (4 - base64Text.Length % 4) % 4, '=');
            byte[] data = Convert.FromBase64String(base64Text);
            return Encoding.UTF8.GetString(data);
        }

    }

    public class TokenIsNotValidException : Exception {
        public TokenIsNotValidException() { }
        public TokenIsNotValidException(string message) : base(message) { }
        public TokenIsNotValidException(string message, Exception inner) : base(message, inner) { }
    }

    public class TokenHasExpiredException : Exception {
        public TokenHasExpiredException() { }
        public TokenHasExpiredException(string message) : base(message) { }
        public TokenHasExpiredException(string message, Exception inner) : base(message, inner) { }
    }

    public class TokenHasNotExpiredException : Exception {
        public TokenHasNotExpiredException() { }
        public TokenHasNotExpiredException(string message) : base(message) { }
        public TokenHasNotExpiredException(string message, Exception inner) : base(message, inner) { }
    }

}