﻿//------------------------------------------------------------------------------
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
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents a XmlDsig X509Data element as per:  https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-X509Data
    /// </summary>
    /// <remarks> Supports multiple certificates. </remarks>
    public class X509Data
    {
        /// <summary>
        /// Initializes an instance of <see cref="X509Data"/>.
        /// </summary>
        public X509Data()
        {
        }

        /// <summary>
        /// Initializes an instance of <see cref="X509Data"/>.
        /// </summary>
        public X509Data(X509Certificate2 certificate)
        {
            if (certificate != null)
                Certificates.Add(Convert.ToBase64String(certificate.RawData));
        }


        /// <summary>
        /// Initializes an instance of <see cref="X509Data"/>.
        /// </summary>
        public X509Data(IEnumerable<X509Certificate2> certificates)
        {
            if (certificates != null)
            {
                foreach (var certificate in certificates)
                {
                    if (certificate != null)
                        Certificates.Add(Convert.ToBase64String(certificate.RawData));
                }
            }
        }

        /// <summary>
        /// Gets or sets the 'X509IssuerSerial' that is part of a 'X509Data'.
        /// </summary>
        public IssuerSerial IssuerSerial
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the 'X509SKI' value that is a part of 'X509Data'.
        /// </summary>
        public string SKI
        {
            get;
            set;
        }

        /// <summary>
        /// Get or sets the 'X509SubjectName' value that is a part of 'X509Data'.
        /// </summary>
        public string SubjectName
        {
            get;
            set;
        }

        /// <summary>
        /// Get the collection of X509Certificates that is associated with 'X509Data'.
        /// </summary>
        public ICollection<string> Certificates { get; } = new Collection<string>();

        /// <summary>
        /// Get or sets the 'CRL' value that is a part of 'X509Data'.
        /// </summary>
        public string CRL
        {
            get;
            set;
        }

        /// <summary>
        /// Checks if an 'X509Data' object is empty.
        /// </summary>
        public bool IsEmpty()
        {
            return IssuerSerial == null && SKI == null && SubjectName == null && Certificates.Count == 0 && CRL == null;
        }

        /// <summary>
        /// Compares two X509Data objects.
        /// </summary>
        public override bool Equals(object obj)
        {
            var other = obj as X509Data;
            if (other == null)
                return false;
            else if (!IssuerSerial.Equals(other.IssuerSerial) ||
                string.Compare(SKI, other.SKI, StringComparison.OrdinalIgnoreCase) != 0 || 
                string.Compare(SubjectName, other.SubjectName, StringComparison.OrdinalIgnoreCase) != 0 ||
                // certificates may need to be compared in a special way instead of generic string comparison?
                !Enumerable.SequenceEqual(Certificates.OrderBy(t => t), other.Certificates.OrderBy(t => t)) ||
                string.Compare(CRL, other.CRL, StringComparison.OrdinalIgnoreCase) != 0)
                    return false;
            return true;
        }

        /// <summary>
        /// Serves as a hash function for X509Data.
        /// </summary>
        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

    }
}
