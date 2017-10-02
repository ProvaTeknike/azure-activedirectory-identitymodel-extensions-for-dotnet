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
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using Newtonsoft.Json.Linq;
#if !CrossVersionTokenValidation
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.WsFederation;
#endif

namespace Microsoft.IdentityModel.Tests
{
    public class IdentityComparer
    {
        private static readonly Dictionary<string, Func<object, object, CompareContext, bool>> _equalityDict =
            new Dictionary<string, Func<object, object, CompareContext, bool>>
            {
                { typeof(Collection<SecurityKey>).ToString(), ContinueCheckingEquality },
                { typeof(Dictionary<string, object>).ToString(), AreObjectDictionariesEqual },
                { typeof(Dictionary<string, object>.ValueCollection).ToString(), AreValueCollectionsEqual },
                { typeof(IEnumerable<Claim>).ToString(), AreClaimsEnumsEqual },
                { typeof(IEnumerable<ClaimsIdentity>).ToString(), AreClaimsIdentitiesEnumsEqual },
                { typeof(IEnumerable<object>).ToString(), AreObjectEnumsEqual },
                { typeof(IEnumerable<SecurityKey>).ToString(), AreSecurityKeyEnumsEqual },
                { typeof(IEnumerable<string>).ToString(), AreStringEnumsEqual },
                { typeof(IDictionary<string, string>).ToString(), AreStringDictionariesEqual},
#if !CrossVersionTokenValidation
                { typeof(List<JsonWebKey>).ToString(), AreJsonWebKeyEnumsEqual },
#endif
                { typeof(List<KeyInfo>).ToString(), AreKeyInfoEnumsEqual },
                { typeof(List<SamlAssertion>).ToString(), AreSamlAssertionEnumsEqual},
                { typeof(List<SamlAttribute>).ToString(), AreSamlAttributeEnumsEqual },
                { typeof(List<SamlAuthorityBinding>).ToString(), AreSamlAuthorityBindingEnumsEqual },
                { typeof(List<SamlAction>).ToString(), AreSamlActionEnumsEqual },
                { typeof(List<SamlStatement>).ToString(), AreSamlStatementEnumsEqual },
                { typeof(List<SamlCondition>).ToString(), AreSamlConditionEnumsEqual },
                { typeof(List<SecurityKey>).ToString(), AreSecurityKeyEnumsEqual },
                { typeof(List<Reference>).ToString(), AreReferenceEnumsEqual },
                { typeof(List<Uri>).ToString(), AreUriEnumsEqual },
                { typeof(List<X509Data>).ToString(), AreX509DataEnumsEqual },
                { typeof(X509Certificate2).ToString(), AreX509Certificate2Equal },
                { typeof(AuthenticationProtocolMessage).ToString(), CompareAllPublicProperties },
                { typeof(byte[]).ToString(), AreBytesEqual },
                { typeof(Claim).ToString(), CompareAllPublicProperties },
                { typeof(ClaimsIdentity).ToString(), CompareAllPublicProperties },
                { typeof(ClaimsPrincipal).ToString(), CompareAllPublicProperties },
                { typeof(IssuerSerial).ToString(), CompareAllPublicProperties },
                { typeof(JArray).ToString(), AreJArraysEqual },
#if !CrossVersionTokenValidation
                { typeof(JsonWebKey).ToString(), CompareAllPublicProperties },
                { typeof(JsonWebKeySet).ToString(), CompareAllPublicProperties },
                { typeof(JwtHeader).ToString(), CompareAllPublicProperties },
                { typeof(JwtPayload).ToString(), CompareAllPublicProperties },
                { typeof(JwtSecurityToken).ToString(), CompareAllPublicProperties },
                { typeof(JwtSecurityTokenHandler).ToString(), CompareAllPublicProperties },
#endif
                { typeof(KeyInfo).ToString(), CompareAllPublicProperties },
                { typeof(OpenIdConnectConfiguration).ToString(), CompareAllPublicProperties },
                { typeof(OpenIdConnectMessage).ToString(), CompareAllPublicProperties },
                { typeof(Reference).ToString(), CompareAllPublicProperties },
                { typeof(RSAKeyValue).ToString(), CompareAllPublicProperties },
                { typeof(RsaSecurityKey).ToString(), CompareAllPublicProperties },
                { typeof(RSAParameters).ToString(), AreRsaParametersEqual },
                { typeof(SamlAction).ToString(), CompareAllPublicProperties },
                { typeof(SamlAudienceRestrictionCondition).ToString(), CompareAllPublicProperties },
                { typeof(SamlAssertion).ToString(), CompareAllPublicProperties},
                { typeof(SamlAttribute).ToString(), CompareAllPublicProperties },
                { typeof(SamlAttributeStatement).ToString(), CompareAllPublicProperties },
                { typeof(SamlAuthenticationStatement).ToString(), CompareAllPublicProperties },
                { typeof(SamlAuthorityBinding).ToString(), CompareAllPublicProperties },
                { typeof(SamlAuthorizationDecisionStatement).ToString(), CompareAllPublicProperties },
                { typeof(SamlCondition).ToString(), CompareAllPublicProperties },
                { typeof(SamlDoNotCacheCondition).ToString(), CompareAllPublicProperties },
                { typeof(SamlSecurityToken).ToString(), CompareAllPublicProperties },
#if !CrossVersionTokenValidation
                { typeof(SamlSecurityTokenHandler).ToString(), CompareAllPublicProperties },
#endif
                { typeof(Saml2SecurityToken).ToString(), CompareAllPublicProperties },
#if !CrossVersionTokenValidation
                { typeof(Saml2SecurityTokenHandler).ToString(), CompareAllPublicProperties },
#endif
                { typeof(SamlStatement).ToString(), CompareAllPublicProperties },
                { typeof(SecurityKey).ToString(), CompareAllPublicProperties },
                { typeof(SecurityToken).ToString(), CompareAllPublicProperties},
                { typeof(SecurityTokenHandler).ToString(), CompareAllPublicProperties},
                { typeof(Signature).ToString(), CompareAllPublicProperties },
                { typeof(SignedInfo).ToString(), CompareAllPublicProperties },
                { typeof(SigningCredentials).ToString(), CompareAllPublicProperties },
                { typeof(string).ToString(), AreStringsEqual },
                { typeof(SymmetricSecurityKey).ToString(), CompareAllPublicProperties },
                { typeof(TokenValidationParameters).ToString(), CompareAllPublicProperties },
                { typeof(WsFederationConfiguration).ToString(), CompareAllPublicProperties },
                { typeof(WsFederationMessage).ToString(), CompareAllPublicProperties },
                { typeof(Uri).ToString(), AreUrisEqual },
                { typeof(X509Data).ToString(), CompareAllPublicProperties },
            };

#if !CrossVersionTokenValidation
        public static bool AreJsonWebKeyEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<JsonWebKey>(object1 as IEnumerable<JsonWebKey>, object2 as IEnumerable<JsonWebKey>, context, AreEqual);
        }
#endif
        public static bool AreKeyInfoEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<KeyInfo>(object1 as IEnumerable<KeyInfo>, object2 as IEnumerable<KeyInfo>, context, AreEqual);
        }

        public static bool AreObjectEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<object>(object1 as IEnumerable<object>, object2 as IEnumerable<object>, context, AreObjectsEqual);
        }

        public static bool AreReferenceEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<Reference>(object1 as IEnumerable<Reference>, object2 as IEnumerable<Reference>, context, AreEqual);
        }

        public static bool AreUriEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<Uri>(object1 as IEnumerable<Uri>, object2 as IEnumerable<Uri>, context, AreEqual);
        }

        public static bool AreSamlAttributeEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<SamlAttribute>(object1 as IEnumerable<SamlAttribute>, object2 as IEnumerable<SamlAttribute>, context, AreEqual);
        }

        public static bool AreSamlConditionEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<SamlCondition>(object1 as IEnumerable<SamlCondition>, object2 as IEnumerable<SamlCondition>, context, AreEqual);
        }

        public static bool AreSamlStatementEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<SamlStatement>(object1 as IEnumerable<SamlStatement>, object2 as IEnumerable<SamlStatement>, context, AreEqual);
        }

        public static bool AreSamlActionEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<SamlAction>(object1 as IEnumerable<SamlAction>, object2 as IEnumerable<SamlAction>, context, AreEqual);
        }

        public static bool AreSamlAuthorityBindingEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<SamlAuthorityBinding>(object1 as IEnumerable<SamlAuthorityBinding>, object2 as IEnumerable<SamlAuthorityBinding>, context, AreEqual);
        }

        public static bool AreSamlAssertionEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<SamlAssertion>(object1 as IEnumerable<SamlAssertion>, object2 as IEnumerable<SamlAssertion>, context, AreEqual);
        }

        public static bool AreStringEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<string>(object1 as IEnumerable<string>, object2 as IEnumerable<string>, context, AreStringsEqual);
        }

        public static bool AreSecurityKeyEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<SecurityKey>(object1 as IEnumerable<SecurityKey>, object2 as IEnumerable<SecurityKey>, context, AreSecurityKeysEqual);
        }

        public static bool AreX509DataEnumsEqual(object object1, object object2, CompareContext context)
        {
            return AreEnumsEqual<X509Data>(object1 as IEnumerable<X509Data>, object2 as IEnumerable<X509Data>, context, AreEqual);
        }

        public static bool AreEnumsEqual<T>(IEnumerable<T> t1, IEnumerable<T> t2, CompareContext context, Func<T, T, CompareContext, bool> areEqual)
        {
            List<T> toMatch = new List<T>(t1);
            List<T> expectedValues = new List<T>(t2);
            if (toMatch.Count != expectedValues.Count)
            {
                context.Diffs.Add("toMatch.Count != expectedToMatch.Count: " + toMatch.Count + ", " + expectedValues.Count + ", typeof: " + t1.GetType().ToString());
                return false;
            }

            int numMatched = 0;
            int numToMatch = toMatch.Count;
            CompareContext localContext = new CompareContext(context);
            List<KeyValuePair<T,T>> matchedTs = new List<KeyValuePair<T,T>>();
            
            // helps debugging to see what didn't match
            List<T> notMatched = new List<T>();
            foreach (var t in t1)
            {
                var perItemContext = new CompareContext(localContext);
                bool matched = false;
                for (int i = 0; i < expectedValues.Count; i++)
                {
                    if (areEqual(t, expectedValues[i], perItemContext))
                    {
                        numMatched++;
                        matchedTs.Add(new KeyValuePair<T, T>(expectedValues[i], t));
                        matched = true;
                        expectedValues.RemoveAt(i);
                        perItemContext.Diffs.Clear();
                        break;
                    }

                    perItemContext.Diffs.Add("===========================\n\r");
                }

                if (!matched)
                {
                    notMatched.Add(t);
                    localContext.Diffs.AddRange(perItemContext.Diffs);
                }
            }

            if (numMatched != numToMatch)
            {
                localContext.Diffs.Add("numMatched != numToMatch: " + numMatched + ", " + numToMatch);
                if (notMatched.Count > 0)
                {
                    localContext.Diffs.Add(Environment.NewLine + "items in first enumeration NOT Matched");
                    foreach (var item in notMatched)
                    {
                        if (item != null)
                            localContext.Diffs.Add(item.ToString());
                        else
                            localContext.Diffs.Add("item is null");
                    }
                }

                if (expectedValues.Count > 0)
                {
                    localContext.Diffs.Add(Environment.NewLine + "expectedValues NOT Matched");
                    foreach (var item in expectedValues)
                    {
                        if (item != null)
                            localContext.Diffs.Add(item.ToString());
                        else
                            localContext.Diffs.Add("item is null");
                    }
                }

                if (matchedTs.Count > 0)
                {
                    localContext.Diffs.Add(Environment.NewLine + "items that were Matched");
                    foreach (var item in matchedTs)
                    {
                        localContext.Diffs.Add(item.Key.ToString());
                    }
                }
            }

            return context.Merge(localContext);
        }

        public static bool AreClaimsEnumsEqual(object object1, object object2, CompareContext context)
        {

            IEnumerable<Claim> t1 = (IEnumerable<Claim>)object1;
            IEnumerable<Claim> t2 = (IEnumerable<Claim>)object2;

            var claims1 = new List<Claim>(t1);
            var claims2 = new List<Claim>(t2);
            if (claims1.Count != claims2.Count)
            {
                context.Diffs.Add($"claims1.Count != claims2.Count: {claims1.Count}, {claims2.Count}");
                context.Diffs.Add("claims1:");
                foreach (var claim in claims1)
                    context.Diffs.Add(claim.Type + ": " + claim.Value + ": " + claim.ValueType + ": " + claim.Issuer + ": " + claim.OriginalIssuer);

                context.Diffs.Add("claims2:");
                foreach (var claim in claims2)
                    context.Diffs.Add(claim.Type + ": " + claim.Value + ": " + claim.ValueType + ": " + claim.Issuer + ": " + claim.OriginalIssuer);
            }

            int numMatched = 0;
            int numToMatch = claims1.Count;
            var localContext = new CompareContext(context);
            var matchedClaims = new List<Claim>();
            var notMatched = new List<Claim>();
            foreach (var t in t1)
            {
                var perClaimContext = new CompareContext(localContext);
                bool matched = false;
                for (int i = 0; i < claims2.Count; i++)
                {
                    if (AreClaimsEqual(t, claims2[i], perClaimContext))
                    {
                        numMatched++;
                        matchedClaims.Add(t);
                        matched = true;
                        claims2.RemoveAt(i);
                        break;
                    }
                }

                if (!matched)
                    notMatched.Add(t);
            }

            if (numMatched != numToMatch)
            {
                localContext.Diffs.Add(Environment.NewLine + "numMatched != numToMatch: " + numMatched + ", " + numToMatch);
                localContext.Diffs.Add(Environment.NewLine + "Claims1 NOT Matched:" + Environment.NewLine);
                foreach (var claim in notMatched)
                    localContext.Diffs.Add(claim.Type + ": " + claim.Value + ": " + claim.ValueType + ": " + claim.Issuer + ": " + claim.OriginalIssuer);

                localContext.Diffs.Add(Environment.NewLine + "Claims2 NOT Matched:" + Environment.NewLine);
                foreach (var claim in claims2)
                    localContext.Diffs.Add(claim.Type + ": " + claim.Value + ": " + claim.ValueType + ": " + claim.Issuer + ": " + claim.OriginalIssuer);

                localContext.Diffs.Add(Environment.NewLine + "Claims Matched:" + Environment.NewLine);
                foreach (var claim in matchedClaims)
                    localContext.Diffs.Add(claim.Type + ": " + claim.Value + ": " + claim.ValueType + ": " + claim.Issuer + ": " + claim.OriginalIssuer);

                localContext.Diffs.Add(Environment.NewLine);
            }

            return context.Merge(localContext);
        }

        public static bool AreClaimsIdentitiesEnumsEqual(Object object1, Object object2, CompareContext context)
        {
            IEnumerable<ClaimsIdentity> t1 = (IEnumerable<ClaimsIdentity>)object1;
            IEnumerable<ClaimsIdentity> t2 = (IEnumerable<ClaimsIdentity>)object2;

            if (t1 == null && t2 == null)
                return true;

            if (t1 == null)
            {
                context.Diffs.Add("t1 == null, t2 != null");
                return false;
            }

            if (t2 == null)
            {
                context.Diffs.Add("t1 != null, t2 == null");
                return false;
            }

            if (ReferenceEquals(t1, t2))
                return true;

            var claimsIdentity1 = new List<ClaimsIdentity>(t1);
            var claimsIdentity2 = new List<ClaimsIdentity>(t2);
            if (claimsIdentity1.Count != claimsIdentity2.Count)
            {
                context.Diffs.Add($"claimsIdentity1.Count != claimsIdentity2.Count: {claimsIdentity1.Count}, {claimsIdentity2.Count}");
                context.Diffs.Add("claimsIdentity1:");
                foreach (var identity in claimsIdentity1)
                    context.Diffs.Add(identity.Name + ": " + identity.Label + ": " + identity.IsAuthenticated + ": " + identity.AuthenticationType + ": " + identity.RoleClaimType + ": " + identity.NameClaimType);

                context.Diffs.Add("claimsIdentity2:");
                foreach (var identity in claimsIdentity2)
                    context.Diffs.Add(identity.Name + ": " + identity.Label + ": " + identity.IsAuthenticated + ": " + identity.AuthenticationType + ": " + identity.RoleClaimType + ": " + identity.NameClaimType);
            }

            int numMatched = 0;
            int numToMatch = claimsIdentity1.Count;
            var localContext = new CompareContext(context);
            var matchedClaimsIdentities = new List<ClaimsIdentity>();
            var notMatched = new List<ClaimsIdentity>();
            foreach (var t in t1)
            {
                var perClaimContext = new CompareContext(localContext);
                bool matched = false;
                for (int i = 0; i < claimsIdentity2.Count; i++)
                {
                    if (AreClaimsIdentitiesEqual(t, claimsIdentity2[i], perClaimContext))
                    {
                        numMatched++;
                        matchedClaimsIdentities.Add(t);
                        matched = true;
                        claimsIdentity2.RemoveAt(i);
                        break;
                    }
                }

                if (!matched)
                    notMatched.Add(t);
            }

            if (numMatched != numToMatch)
            {
                localContext.Diffs.Add(Environment.NewLine + "numMatched != numToMatch: " + numMatched + ", " + numToMatch);
                localContext.Diffs.Add(Environment.NewLine + "claimsIdentity1 NOT Matched:" + Environment.NewLine);
                foreach (var identity in notMatched)
                    localContext.Diffs.Add(identity.Name + ": " + identity.Label + ": " + identity.IsAuthenticated + ": " + identity.AuthenticationType + ": " + identity.RoleClaimType + ": " + identity.NameClaimType);

                localContext.Diffs.Add(Environment.NewLine + "claimsIdentity2 NOT Matched:" + Environment.NewLine);
                foreach (var identity in claimsIdentity2)
                    localContext.Diffs.Add(identity.Name + ": " + identity.Label + ": " + identity.IsAuthenticated + ": " + identity.AuthenticationType + ": " + identity.RoleClaimType + ": " + identity.NameClaimType);

                localContext.Diffs.Add(Environment.NewLine + "claimsIdentity Matched:" + Environment.NewLine);
                foreach (var identity in matchedClaimsIdentities)
                    localContext.Diffs.Add(identity.Name + ": " + identity.Label + ": " + identity.IsAuthenticated + ": " + identity.AuthenticationType + ": " + identity.RoleClaimType + ": " + identity.NameClaimType);

                localContext.Diffs.Add(Environment.NewLine);
            }

            return context.Merge(localContext);
        }

        public static bool AreEqual(object t1, object t2)
        {
            return AreEqual(t1, t2, CompareContext.Default);
        }

        public static bool AreEqual(object t1, object t2, CompareContext context)
        {
            var localContext = new CompareContext(context);
          
            // Check if either t1 or t2 are null or references of each other to see if we can terminate early.
            if (!ContinueCheckingEquality(t1, t2, localContext))
                return context.Merge(localContext);

            string inter;
            // Use a special function for comparison if required by the specific class of the object.
            if (_equalityDict.TryGetValue(t1.GetType().ToString(), out Func<Object, object, CompareContext, bool> areEqual))
            {
                areEqual(t1, t2, localContext);
            } 
            // Check if any of the interfaces that the class uses require a special function.
            else if ((inter = t1.GetType().GetInterfaces().Select(t => t.ToString()).Intersect(_equalityDict.Keys).FirstOrDefault()) != null)
            {
                _equalityDict[inter](t1, t2, localContext);
            }

            return context.Merge(localContext);
        }

        public static bool AreJArraysEqual(Object object1, Object object2, CompareContext context)
        {
            var a1 = (JArray)object1;
            var a2 = (JArray)object2;
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(a1, a2, localContext))
                return context.Merge(localContext);

            if (a1.Count != a2.Count)
            {
                localContext.Diffs.Add("Count:");
                localContext.Diffs.Add($"a1.Count != a2.Count. '{a1.Count}' : '{a2.Count}'");
            }

            return context.Merge(localContext);
        }

        private static bool AreObjectsEqual(object object1, object object2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(object1, object2, localContext))
                return context.Merge(localContext);

            AreEqual(object1, object2, localContext);

            return context.Merge(localContext);
        }

        private static bool AreValueCollectionsEqual(Object object1, Object object2, CompareContext context)
        {
            Dictionary<string, object>.ValueCollection vc1 = (Dictionary<string, object>.ValueCollection)object1;
            Dictionary<string, object>.ValueCollection vc2 = (Dictionary<string, object>.ValueCollection)object2;
            return true;
        }

        public static bool AreBytesEqual(object object1, object object2, CompareContext context)
        {
            var bytes1 = (byte[]) object1;
            var bytes2 = (byte[]) object2;

            var localContext = new CompareContext(context);
            if (bytes1 == null && bytes2 == null)
            {
                return true;
            }

            if (bytes1 == null || bytes2 == null)
            {
                localContext.Diffs.Add("(bytes1 == null || bytes2 == null)");
            }

            if (bytes1.Length != bytes2.Length)
            {
                localContext.Diffs.Add("(bytes1.Length != bytes2.Length)");
            }
            else
            {
                for (int i = 0; i < bytes1.Length; i++)
                {
                    if (bytes1[i] != bytes2[i])
                    {
                        localContext.Diffs.Add($"'{bytes1}'");
                        localContext.Diffs.Add("!=");
                        localContext.Diffs.Add($"'{bytes2}'");
                    }
                }
            }
           
            return context.Merge(localContext);
        }

        public static bool AreClaimsEqual(Claim claim1, Claim claim2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(claim1, claim2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(claim1, claim2, localContext);
            return context.Merge(localContext);
        }

        public static bool AreClaimsIdentitiesEqual(ClaimsIdentity identity1, ClaimsIdentity identity2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(identity1, identity2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(identity1, identity2, localContext);
            return context.Merge(localContext);
        }

        public static bool AreClaimsPrincipalsEqual(ClaimsPrincipal principal1, ClaimsPrincipal principal2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(principal1, principal2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(principal1, principal2, localContext);
            return context.Merge(localContext);
        }

        public static bool AreObjectDictionariesEqual(Object object1, Object object2, CompareContext context)
        {
            IDictionary<string, object> dictionary1 = (IDictionary<string, object>)object1;
            IDictionary<string, object> dictionary2 = (IDictionary<string, object>)object2;

            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(dictionary1, dictionary2, localContext))
                return context.Merge(localContext);

            if (dictionary1.Count != dictionary2.Count)
                localContext.Diffs.Add($"(dictionary1.Count != dictionary2.Count: {dictionary1.Count}, {dictionary2.Count})");

            int numMatched = 0;
            foreach (string key in dictionary1.Keys)
            {
                if (dictionary2.ContainsKey(key))
                {
                    if (dictionary1[key].GetType() != dictionary2[key].GetType())
                    {
                        localContext.Diffs.Add($"dictionary1[{key}].GetType() != dictionary2[{key}].GetType(). '{dictionary1[key].GetType()}' : '{dictionary2[key].GetType()}'");
                        continue;
                    }

                    var obj1 = dictionary1[key];
                    var obj2 = dictionary2[key];
                    if (obj1.GetType().BaseType == typeof(System.ValueType))
                    {
                        if (!obj1.Equals(obj2))
                            localContext.Diffs.Add(BuildStringDiff(key, obj1, obj2));
                    }
                    else
                    {
                        if (AreEqual(obj1, obj2, context))
                            numMatched++;
                    }
                }
                else
                {
                    localContext.Diffs.Add("dictionary1[key] ! found in dictionary2. key: " + key);
                }
            }

            return context.Merge(localContext);
        }

        public static bool AreStringDictionariesEqual(Object object1, Object object2, CompareContext context)
        {
            IDictionary<string, string> dictionary1 = (IDictionary<string, string>)object1;
            IDictionary<string, string> dictionary2 = (IDictionary<string, string>)object2;

            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(dictionary1, dictionary2, localContext))
                return context.Merge(localContext);

            if (dictionary1.Count != dictionary2.Count)
                localContext.Diffs.Add($"(dictionary1.Count != dictionary2.Count: {dictionary1.Count}, {dictionary2.Count})");

            int numMatched = 0;
            foreach (string key in dictionary1.Keys)
            {
                if (dictionary2.ContainsKey(key))
                {
                    if (!dictionary1[key].Equals(dictionary2[key]))
                    {
                        localContext.Diffs.Add($"dictionary1[key] != dictionary2[key], key: '{key}' value1, value2: '{dictionary1[key]}' + '{dictionary2[key]}'");
                    }
                    else
                    {
                        numMatched++;
                    }
                }
                else
                {
                    localContext.Diffs.Add("dictionary1[key] ! found in dictionary2. key: " + key);
                }
            }

            context.Diffs.AddRange(localContext.Diffs);
            return localContext.Diffs.Count == 0;
        }

#if !CrossVersionTokenValidation
        public static bool AreJwtSecurityTokensEqual(JwtSecurityToken jwt1, JwtSecurityToken jwt2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(jwt1, jwt2, localContext))
                return context.Merge(localContext);

            CompareAllPublicProperties(jwt1, jwt2, localContext);
            return context.Merge(localContext);
        }
#endif

        public static bool AreSecurityKeysEqual(SecurityKey securityKey1, SecurityKey securityKey2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(securityKey1, securityKey2, localContext))
                return context.Merge(localContext);

            // X509SecurityKey doesn't have to use reflection to get cert.
            X509SecurityKey x509Key1 = securityKey1 as X509SecurityKey;
            X509SecurityKey x509Key2 = securityKey2 as X509SecurityKey;
            if (x509Key1 != null && x509Key2 != null)
                CompareAllPublicProperties(x509Key1, x509Key2, localContext);

            SymmetricSecurityKey symKey1 = securityKey1 as SymmetricSecurityKey;
            SymmetricSecurityKey symKey2 = securityKey2 as SymmetricSecurityKey;
            if (symKey1 != null && symKey2 != null)
                CompareAllPublicProperties(symKey1, symKey2, localContext);

            RsaSecurityKey rsaKey1 = securityKey1 as RsaSecurityKey;
            RsaSecurityKey rsaKey2 = securityKey2 as RsaSecurityKey;
            if (rsaKey1 != null && rsaKey2 != null)
            {
                CompareAllPublicProperties(rsaKey1, rsaKey2, localContext);
            }

            return context.Merge(localContext);
        }

        public static bool AreRsaParametersEqual(object object1, object object2, CompareContext context)
        {
            RSAParameters rsaParameters1 = (RSAParameters) object1;
            RSAParameters rsaParameters2 = (RSAParameters) object2;

            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(rsaParameters1, rsaParameters2, localContext))
                return context.Merge(localContext);

            if (!AreBytesEqual(rsaParameters1.D, rsaParameters2.D, context))
            {
                localContext.Diffs.Add("D:");
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.D, rsaParameters2.D)");
            }

            if (!AreBytesEqual(rsaParameters1.DP, rsaParameters2.DP, context))
            {
                localContext.Diffs.Add("DP:");
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.DP, rsaParameters2.DP)");
            }

            if (!AreBytesEqual(rsaParameters1.DQ, rsaParameters2.DQ, context))
            {
                localContext.Diffs.Add("DQ:");
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.DQ, rsaParameters2.DQ)");
            }

            if (!AreBytesEqual(rsaParameters1.Exponent, rsaParameters2.Exponent, context))
            {
                localContext.Diffs.Add("Exponent:");
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.Exponent, rsaParameters2.Exponent)");
            }

            if (!AreBytesEqual(rsaParameters1.InverseQ, rsaParameters2.InverseQ, context))
            {
                localContext.Diffs.Add("InverseQ:");
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.InverseQ, rsaParameters2.InverseQ)");
            }

            if (!AreBytesEqual(rsaParameters1.Modulus, rsaParameters2.Modulus, context))
            {
                localContext.Diffs.Add("Modulus:");
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.Modulus, rsaParameters2.Modulus)");
            }

            if (!AreBytesEqual(rsaParameters1.P, rsaParameters2.P, context))
            {
                localContext.Diffs.Add("P:");
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.P, rsaParameters2.P)");
            }

            if (!AreBytesEqual(rsaParameters1.Q, rsaParameters2.Q, context))
            {
                localContext.Diffs.Add("Q:");
                localContext.Diffs.Add("!AreBytesEqual(rsaParameters1.Q, rsaParameters2.Q)");
            }

            return context.Merge(localContext);
        }

        public static bool AreStringsEqual(object object1, object object2, CompareContext context)
        {
            string str1 = (string)object1;
            string str2 = (string)object2;

            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(str1, str2, localContext))
                return context.Merge(localContext);

            if (string.IsNullOrEmpty(str1) && string.IsNullOrEmpty(str2))
                return true;

            if (ReferenceEquals(str1, str2))
                return true;

            if (str1 == null || str2 == null)
                localContext.Diffs.Add("(str1 == null || str2 == null)");

            if (!string.Equals(str1, str2, context.StringComparison))
            {
                localContext.Diffs.Add($"'{str1}'");
                localContext.Diffs.Add($"!=");
                localContext.Diffs.Add($"'{str2}'");
                localContext.Diffs.Add($"'{context.StringComparison}'");
            }

            return context.Merge(localContext);
        }

        public static bool AreUrisEqual(object object1, object object2, CompareContext context)
        {
            Uri uri1 = (Uri)object1;
            Uri uri2 = (Uri)object2;

            var localContext = new CompareContext(context);
            if (!ContinueCheckingEquality(uri1, uri2, localContext))
                return context.Merge(localContext);

            if (!string.Equals(uri1.OriginalString, uri2.OriginalString, context.StringComparison))
            {
                localContext.Diffs.Add($"'{uri1.OriginalString}'");
                localContext.Diffs.Add($"!=");
                localContext.Diffs.Add($"'{uri2.OriginalString}'");
                localContext.Diffs.Add($"'{context.StringComparison}'");
            }

            return context.Merge(localContext);
        }

        public static bool AreKeyInfosEqual(KeyInfo keyInfo1, KeyInfo keyInfo2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(keyInfo1, keyInfo2, context))
                CompareAllPublicProperties(keyInfo1, keyInfo2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreSignedInfosEqual(SignedInfo signedInfo1, SignedInfo signedInfo2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(signedInfo1, signedInfo2, localContext))
                CompareAllPublicProperties(signedInfo1, signedInfo2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreWsFederationConfigurationsEqual(WsFederationConfiguration configuration1, WsFederationConfiguration configuration2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(configuration1, configuration2, localContext))
                CompareAllPublicProperties(configuration1, configuration2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreWsFederationMessagesEqual(WsFederationMessage message1, WsFederationMessage message2, CompareContext context)
        {
            var localContext = new CompareContext(context);
            if (ContinueCheckingEquality(message1, message2, localContext))
                CompareAllPublicProperties(message1, message2, localContext);

            return context.Merge(localContext);
        }

        public static bool AreX509Certificate2Equal(object object1, object object2, CompareContext context)
        {
            var certificate1 = (X509Certificate2)object1;
            var certificate2 = (X509Certificate2)object2;

            var localContext = new CompareContext(context);

            if (certificate1 == null && certificate2 == null)
                return true;

            if (certificate1 == null || certificate2 == null || !certificate1.Equals(certificate2))
            {
                localContext.Diffs.Add("X509Certificate2:");
                if (certificate1 == null)
                    localContext.Diffs.Add($"certificate: null");
                else
                    localContext.Diffs.Add($"certificate: {certificate1}");
                localContext.Diffs.Add("!=");
                if (certificate2 == null)
                    localContext.Diffs.Add($"certificate: null");
                else
                    localContext.Diffs.Add($"certificate: {certificate2}");
            }

            return context.Merge(localContext);
        }

        public static string BuildStringDiff(string label, object str1, object str2)
        {
            return (label ?? "label") + ": '" + GetString(str1) + "', '" + GetString(str2) + "'";
        }

        public static bool CompareAllPublicProperties(object obj1, object obj2, CompareContext context)
        {
            Type type = obj1.GetType();
            var localContext = new CompareContext(context);

            // public instance properties
            var propertyInfos = type.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

            // Touch each public property
            foreach (var propertyInfo in propertyInfos)
            {
                var propertyContext = new CompareContext(context);
                try
                {
                    if (type == typeof(Claim))
                    {
                        if (context.IgnoreSubject && propertyInfo.Name == "Subject")
                            continue;

                        if (context.IgnoreProperties && propertyInfo.Name == "Properties")
                            continue;
                    }

                    if (propertyInfo.GetMethod != null)
                    {
                        object val1 = propertyInfo.GetValue(obj1, null);
                        object val2 = propertyInfo.GetValue(obj2, null);
                        if ((val1 == null) && (val2 == null))
                            continue;

                        if ((val1 == null) || (val2 == null))
                        {
                            localContext.Diffs.Add($"{propertyInfo.Name}:");
                            localContext.Diffs.Add(BuildStringDiff(propertyInfo.Name, val1, val2));
                        }
#if CrossVersionTokenValidation
                        else if (type == typeof(ClaimsIdentity) && String.Equals(Convert.ToString(val1), AuthenticationTypes.Federation, StringComparison.Ordinal) && String.Equals(Convert.ToString(val2), "AuthenticationTypes.Federation", StringComparison.Ordinal))
                        {
                            continue;
                        }
#endif
                        else if (val1.GetType().BaseType == typeof(System.ValueType) && !_equalityDict.Keys.Contains(val1.GetType().ToString()))
                        {
                            if (!val1.Equals(val2))
                            {
                                localContext.Diffs.Add($"{propertyInfo.Name}:");
                                localContext.Diffs.Add(BuildStringDiff(propertyInfo.Name, val1, val2));
                            }
                        }
                        else
                        {
                            AreEqual(val1, val2, propertyContext);
                            localContext.Merge($"{propertyInfo.Name}:", propertyContext);
                        }
                    }
                }
                catch (Exception ex)
                {
                    localContext.Diffs.Add($"Reflection failed getting 'PropertyInfo: {propertyInfo.Name}'. Exception: '{ex}'.");
                }
            }

            return context.Merge($"CompareAllPublicProperties: {type}", localContext);
        }

        public static bool ContinueCheckingEquality(object obj1, object obj2, CompareContext context)
        {
            if (obj1 == null && obj2 == null)
                return false;

            if (obj1 == null)
            {
                context.Diffs.Add(BuildStringDiff(obj2.GetType().ToString(), obj1, obj2));
                return false;
            }

            if (obj2 == null)
            {
                context.Diffs.Add(BuildStringDiff(obj1.GetType().ToString(), obj1, obj2));
                return false;
            }

            if (object.ReferenceEquals(obj1, obj2))
                return false;

            if (!context.IgnoreType && (obj1.GetType() != obj2.GetType()))
                context.Diffs.Add($"obj1.GetType() != obj2.GetType(). '{obj1} : {obj2}'");

            return true;
        }

        private static string GetString(object str)
        {
            if (str is string retval)
                return retval;

            if (str is IEnumerable<string> enum1)
                return TestUtilities.SerializeAsSingleCommaDelimitedString(enum1);

            else
                return string.Format(CultureInfo.InvariantCulture, "{0}", (str ?? "null"));
        }
    }
}
