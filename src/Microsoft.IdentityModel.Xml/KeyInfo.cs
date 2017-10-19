//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

[assembly: InternalsVisibleTo("Microsoft.IdentityModel.Tokens.Saml, PublicKey=0024000004800000940000000602000000240000525341310004000001000100b5fc90e7027f67" +
"871e773a8fde8938c81dd402ba65b9201d60593e96c492651e889cc13f1415ebb53fac1131ae0b" +
"d333c5ee6021672d9718ea31a8aebd0da0072f25d87dba6fc90ffd598ed4da35e44c398c454307" +
"e8e33b8426143daec9f596836f97c8f74750e5975c64e2189f45def46b2a2b1247adc3652bf5c3" +
"08055da9")]

namespace Microsoft.IdentityModel.Xml
{

    /// <summary>
    /// Represents a XmlDsig KeyInfo element as per:  https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-KeyInfo
    /// </summary>
    /// <remarks>Only a single 'X509Certificate' is supported. Multiples that include intermediate and root certs are not supported.</remarks>
    public class KeyInfo
    {
        // TODO - IssuerSerial needs to have a structure as 'IssuerName' and 'SerialNumber'
        /// <summary>
        /// Initializes an instance of <see cref="KeyInfo"/>.
        /// </summary>
        public KeyInfo()
        {
        }

        /// <summary>
        /// Initializes an instance of <see cref="KeyInfo"/>.
        /// </summary>
        /// <param name="certificate">the <see cref="X509Certificate2"/>to populate the X509Data.</param>
        public KeyInfo(X509Certificate2 certificate)
        {
            var data = new X509Data(certificate);
            X509Data.Add(data);
        }

        /// <summary>
        /// Initializes an instance of <see cref="KeyInfo"/>.
        /// </summary>
        /// <param name="key">the <see cref="SecurityKey"/>to populate the <see cref="KeyInfo"/>.</param>
        public KeyInfo(SecurityKey key)
        {
            if (key is X509SecurityKey x509Key)
            {
                var data = new X509Data();
                data.Certificates.Add(Convert.ToBase64String(x509Key.Certificate.RawData));
                X509Data.Add(data);
            }
            else if (key is RsaSecurityKey rsaKey)
            {
                var rsaParameters = rsaKey.Parameters;

                // Obtain parameters from the RSA if the rsaKey does not contain a valid value for RSAParameters
                if (rsaKey.Parameters.Equals(default(RSAParameters)))
                    rsaParameters = rsaKey.Rsa.ExportParameters(false);
        
                RSAKeyValue = new RSAKeyValue(Base64UrlEncoder.Encode(rsaParameters.Modulus), Base64UrlEncoder.Encode(rsaParameters.Exponent));
            }
        }

        /// <summary>
        /// Gets or sets the 'KeyName' that can be used as a key identifier.
        /// </summary>
        public string KeyName
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the Uri associated with the RetrievalMethod
        /// </summary>
        public string RetrievalMethodUri
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the RSAKeyValue.
        /// </summary>
        public RSAKeyValue RSAKeyValue
        {
            get;
            set;
        }

        /// <summary>
        /// Gets the 'X509Data' value.
        /// </summary>
        public ICollection<X509Data> X509Data { get; } = new Collection<X509Data>();

        /// <summary>
        /// Compares two KeyInfo objects.
        /// </summary>
        public override bool Equals(object obj)
        {   
            KeyInfo other = obj as KeyInfo;
            if (other == null)
                return false;
            else if (string.Compare(KeyName, other.KeyName, StringComparison.OrdinalIgnoreCase) != 0
                ||string.Compare(RetrievalMethodUri, other.RetrievalMethodUri, StringComparison.OrdinalIgnoreCase) != 0
                || (RSAKeyValue != null && !RSAKeyValue.Equals(other.RSAKeyValue)
                || !new HashSet<X509Data>(X509Data).SetEquals(other.X509Data)))
                return false;

            return true;
        }

        /// <summary>
        /// Serves as a hash function for KeyInfo.
        /// </summary>
        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        /// <summary>
        /// Returns true if the KeyInfo object can be matched with the specified SecurityKey, returns false otherwise.
        /// </summary>
        internal bool MatchKey(SecurityKey key)
        {
            if (key is X509SecurityKey x509SecurityKey)
            {
                return Matches(x509SecurityKey);

            }
            else if (key is RsaSecurityKey rsaSecurityKey)
            {
                return Matches(rsaSecurityKey);
            }
            else if (key is JsonWebKey jsonWebKey)
            {
                return Matches(jsonWebKey);
            }

            return false;
        }

        private bool Matches(X509SecurityKey key)
        {
            foreach (var data in X509Data)
            {
                foreach (var certificate in data.Certificates)
                {
                    var cert = new X509Certificate2(Convert.FromBase64String(certificate));
                    if (cert.Equals(key.Certificate))
                        return true;
                }
            }

            return false;
        }

        private bool Matches(RsaSecurityKey key)
        {
            if (!key.Parameters.Equals(default(RSAParameters)))
            {
                return (RSAKeyValue.Exponent.Equals(Base64UrlEncoder.Encode(key.Parameters.Exponent))
                     && RSAKeyValue.Modulus.Equals(Base64UrlEncoder.Encode(key.Parameters.Modulus)));
            }
            else if (key.Rsa != null)
            {
                var parameters = key.Rsa.ExportParameters(false);
                return (RSAKeyValue.Exponent.Equals(Base64UrlEncoder.Encode(parameters.Exponent))
                     && RSAKeyValue.Modulus.Equals(Base64UrlEncoder.Encode(parameters.Modulus)));
            }

            return false;
        }

        private bool Matches(JsonWebKey key)
        {
            if (RSAKeyValue != null)
            {
                return (RSAKeyValue.Exponent.Equals(Base64UrlEncoder.Encode(key.E))
                        && RSAKeyValue.Modulus.Equals(Base64UrlEncoder.Encode(key.N)));
            }

            foreach (var x5c in key.X5c)
            {
                var certToMatch = new X509Certificate2(Convert.FromBase64String(x5c));
                foreach (var data in X509Data)
                {
                    foreach (var certificate in data.Certificates)
                    {
                        var cert = new X509Certificate2(Convert.FromBase64String(certificate));
                        if (cert.Equals(certToMatch))
                            return true;
                    }
                }
            }

            return false;
        }
    }
}
