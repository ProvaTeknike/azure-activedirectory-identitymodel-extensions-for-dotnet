﻿using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.IdentityModel.Tokens
{
    internal class MethodInAssembly
    {
        public delegate AsymmetricAlgorithm GetKeyDelegateAsymmetricAlgorithm(X509Certificate2 certificate);

        public delegate RSA GetKeyDelegateRSA(X509Certificate2 certificate);

        private static GetKeyDelegateAsymmetricAlgorithm _getPrivateKeyDelegateAsymmetricAlgorithm = null;

        private static GetKeyDelegateAsymmetricAlgorithm _getPublicKeyDelegateAsymmetricAlgorithm = null;

        private static GetKeyDelegateRSA _getPrivateKeyDelegateRSA = null;

        private static GetKeyDelegateRSA _getPublicKeyDelegateRSA = null;

        private static bool _delegateSet = false;

        private static void SetDelegate()
        {
            if (_delegateSet)
                return;

            _delegateSet = true;

#if (NET45 || NET451 || NET452)
            Assembly systemCoreAssembly = null;
            foreach (var assem in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (assem.GetName().Name == "System.Core")
                {
                    systemCoreAssembly = assem;
                }
            }

            if (systemCoreAssembly != null)
            {
                Type type = systemCoreAssembly.GetType("System.Security.Cryptography.X509Certificates.RSACertificateExtensions");
                if (type != null)
                {
                    var getPrivateKeyMethod = type.GetMethod("GetRSAPrivateKey");
                    if (getPrivateKeyMethod != null)
                    {
                        _getPrivateKeyDelegateRSA = certificate =>
                        {
                            object[] staticParameters = { certificate };
                            return getPrivateKeyMethod.Invoke(null, staticParameters) as RSA;
                        };
                    }

                    var getPublicKeyMethod = type.GetMethod("GetRSAPublicKey");
                    if (getPublicKeyMethod != null)
                    {
                        _getPublicKeyDelegateRSA = certificate =>
                        {
                            object[] staticParameters = { certificate };
                            return getPublicKeyMethod.Invoke(null, staticParameters) as RSA;
                        };
                    }
                }
            }

            if (_getPrivateKeyDelegateAsymmetricAlgorithm == null)
            {
                _getPrivateKeyDelegateAsymmetricAlgorithm = certificate =>
                {
                    return certificate.PrivateKey;
                };
            }

            if (_getPublicKeyDelegateAsymmetricAlgorithm == null)
            {
                _getPublicKeyDelegateAsymmetricAlgorithm = certificate =>
                {
                    return certificate.PublicKey.Key;
                };
            }
#else
            _getPrivateKeyDelegate = certificate =>
            {
                return RSACertificateExtensions.GetRSAPrivateKey(certificate);
            };

            _getPublicKeyDelegate = certificate =>
            {
                return RSACertificateExtensions.GetRSAPublicKey(certificate);
            };
#endif
        }

        public static void SetPrivateKey(X509Certificate2 certificate, RsaAlgorithm rsaAlgorithm)
        {
            if (_getPrivateKeyDelegateRSA != null)
                rsaAlgorithm.rsa = _getPrivateKeyDelegateRSA(certificate);
            else
                rsaAlgorithm.rsaCryptoServiceProvider = _getPrivateKeyDelegateAsymmetricAlgorithm(certificate) as RSACryptoServiceProvider;
        }

        public static void SetPublicKey(X509Certificate2 certificate, RsaAlgorithm rsaAlgorithm)
        {
            if (_getPublicKeyDelegateRSA != null)
                rsaAlgorithm.rsa = _getPublicKeyDelegateRSA(certificate);
            else
                rsaAlgorithm.rsaCryptoServiceProvider = _getPublicKeyDelegateAsymmetricAlgorithm(certificate) as RSACryptoServiceProvider;
        }
    }
}
