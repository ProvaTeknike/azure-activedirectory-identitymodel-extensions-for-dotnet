using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.IdentityModel.Tokens
{
    internal class MethodInAssembly
    {
        public delegate AsymmetricAlgorithm GetKeyDelegateAsymmetricAlgorithm(X509Certificate2 certificate);

        public delegate RSA GetKeyDelegateRSA(X509Certificate2 certificate);

        public delegate byte[] SignDataDelegate(byte[] data, System.Security.Cryptography.HashAlgorithmName hashAlgorithm, System.Security.Cryptography.RSASignaturePadding padding);

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

#if (NET45 || NET451 || NET452 || NET46)
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
            _getPrivateKeyDelegateRSA = certificate =>
            {
                return RSACertificateExtensions.GetRSAPrivateKey(certificate);
            };

            _getPublicKeyDelegateRSA = certificate =>
            {
                return RSACertificateExtensions.GetRSAPublicKey(certificate);
            };
#endif
        }

        public static void SetPrivateKey(X509Certificate2 certificate, RsaAlgorithm rsaAlgorithm)
        {
            SetDelegate();
#if NETSTANDARD1_4
            rsaAlgorithm.rsa = _getPrivateKeyDelegateRSA(certificate);
#else
            if (_getPrivateKeyDelegateRSA != null)
                rsaAlgorithm.rsa = _getPrivateKeyDelegateRSA(certificate);
            else
                rsaAlgorithm.rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(_getPrivateKeyDelegateAsymmetricAlgorithm(certificate) as RSACryptoServiceProvider);
#endif
        }

        public static void SetPublicKey(X509Certificate2 certificate, RsaAlgorithm rsaAlgorithm)
        {
            SetDelegate();
#if NETSTANDARD1_4
            rsaAlgorithm.rsa = _getPublicKeyDelegateRSA(certificate);
#else
            if (_getPublicKeyDelegateRSA != null)
                rsaAlgorithm.rsa = _getPublicKeyDelegateRSA(certificate);
            else
                rsaAlgorithm.rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(_getPublicKeyDelegateAsymmetricAlgorithm(certificate) as RSACryptoServiceProvider);
#endif
        }

        public static AsymmetricAlgorithm GetPrivateKey(X509Certificate2 certificate)
        {
            SetDelegate();
            if (_getPrivateKeyDelegateRSA != null)
                return _getPrivateKeyDelegateRSA(certificate) as AsymmetricAlgorithm;
            else
                return _getPrivateKeyDelegateAsymmetricAlgorithm(certificate);
        }

        public static AsymmetricAlgorithm GetPublicKey(X509Certificate2 certificate)
        {
            SetDelegate();
            if (_getPublicKeyDelegateRSA != null)
                return _getPublicKeyDelegateRSA(certificate) as AsymmetricAlgorithm;
            else
                return _getPublicKeyDelegateAsymmetricAlgorithm(certificate);
        }
    }
}
