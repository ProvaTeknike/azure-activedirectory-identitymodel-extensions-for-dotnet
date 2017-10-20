using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.IdentityModel.Tokens
{
    internal class MethodInAssembly
    {
        public delegate AsymmetricAlgorithm GetKeyDelegate(X509Certificate2 certificate);

        private static GetKeyDelegate _getPrivateKeyDelegate = null;

        private static GetKeyDelegate _getPublicKeyDelegate = null;

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
                        _getPrivateKeyDelegate = certificate =>
                        {
                            object[] staticParameters = { certificate };
                            return getPrivateKeyMethod.Invoke(null, staticParameters) as AsymmetricAlgorithm;
                        };
                    }

                    var getPublicKeyMethod = type.GetMethod("GetRSAPublicKey");
                    if (getPublicKeyMethod != null)
                    {
                        _getPublicKeyDelegate = certificate =>
                        {
                            object[] staticParameters = { certificate };
                            return getPublicKeyMethod.Invoke(null, staticParameters) as AsymmetricAlgorithm;
                        };
                    }
                }
            }

            if (_getPrivateKeyDelegate == null)
            {
                _getPrivateKeyDelegate = certificate =>
                {
                    return certificate.PrivateKey;
                };
            }

            if (_getPublicKeyDelegate == null)
            {
                _getPublicKeyDelegate = certificate =>
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

        public static AsymmetricAlgorithm GetPrivateKey(X509Certificate2 certificate)
        {
            SetDelegate();
            return _getPrivateKeyDelegate(certificate);
        }

        public static AsymmetricAlgorithm GetPublicKey(X509Certificate2 certificate)
        {
            SetDelegate();
            return _getPublicKeyDelegate(certificate);
        }
    }
}
