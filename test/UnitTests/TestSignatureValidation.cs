using System;
using System.Collections.Specialized;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Http;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.Extensions.Options;
using NUnit.Framework;

namespace UnitTests
{
    public class Tests
    {
        [SetUp]
        public void Setup()
        {
        }


        [Test]
        public void Test_Signature_Validation_DecodedQuerystring()
        {
            // Asp.NET core provides a URL decoded query string that fails the regex check
            // produces InvalidDataException "Invalid Query String" from src/ITfoxtec.Identity.Saml2/Util/RawSaml2QueryString.cs ln 26

            var request = new Saml2AuthnRequest(this.Saml2Config);
            var binding = new Saml2RedirectBinding();
            request.SignatureValidationCertificates = new X509Certificate2[] { this.GetCert() };

            binding.Unbind(this.HttpRequest, request);
        }

        [Test]
        public void Test_Signature_Validation_EncodedQuerystring()
        {
            // Using an encoded querystring it passes the Regex check, but signature validation fails
            // produces InvalidSignatureException "Signature is invalid" from src/ITfoxtec.Identity.Saml2/Bindings/Saml2RedirectBinding.cs ln 184

            var request = new Saml2AuthnRequest(this.Saml2Config);
            var binding = new Saml2RedirectBinding();
            request.SignatureValidationCertificates = new X509Certificate2[] { this.GetCert() };

            var req = this.HttpRequest;
            // req.QueryString = HttpUtility(req.QueryString);
            binding.Unbind(req, request);

        }

        private X509Certificate2 GetCert()
        {
            var value = "MIIDDTCCAfWgAwIBAgIJXgZVaHbbVyRmMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi14eWQxNHk3Ni5ldS5hdXRoMC5jb20wHhcNMjExMTExMTE0MTEwWhcNMzUwNzIxMTE0MTEwWjAkMSIwIAYDVQQDExlkZXYteHlkMTR5NzYuZXUuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6SL14W0w9K2Vyml7yITv8o9lQON4+QmW8XDP/fUH5i8C6ZRYd+F+JuWEw59vR9IAL5n29gXIw99LKVQfn1luXuj6WJY5OXFQE6Poz1j25sr0a6qPgx66BABJRdTe2Iy/lVNvIFY03kQ7GaYu1zoGNwiYxBAmT/2iUsAVrKS8Xkfz8s54Kl7y4ERJyTEotb4rAULC/9tUGJeFkScJx1yPKLVc7ebHplodNL+OWkkYxn73rYhXXGndaRFAimq78/fZvv8+I/2VBf6NV6Hmi+1L87BuJIECWKPbAh2i+M0j/bHhJIs0jdck/tKcO+RlXwuFw4t/z3xjIpvgRLtYcXmRjwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSfOMYe1861BKZCVHxkibPifCgPdjAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBALoLyQkJdR6sHCGVXgb8EwuvW0yp7DBOo3alhNxJyE01nfF0GymI11KigTRl1ApnUEe6+oOOWmjLg+DHxiWdY4zF5YmsaOkYa0c+qPkaxytvcY+FD4wWp/b0Mld9E7lD84x8kuyDHfnNdnryjukN/Et1QuW/LxiHPtE4qKfbJnO2J3v1mM8mhKcy27b1RmLQw853Lauig7pFi2uRSxTtRC+DyfLJVhKEs1STvdsEm7+LcVsbw637OAwOda+J8pLFMAVZyiBlbWVwgPjkIsr+jv/nwE+MVKMjU3PqSzvYjB48njHzHuS8+QXmuhbBwU4EbcsbJgCHxiBDu+bVIa6YpbE=";
            return new X509Certificate2(Convert.FromBase64String(value));
        }

        private HttpRequest HttpRequest
        {
            get
            {
                var req = new HttpRequest
                {
                    Method = "GET",
                    QueryString = "?SAMLRequest=fZFNb4MwDIbP+xcod0agFIoFSJ16WKVNqjq0wy5TCAEiQcLisLX/fnzs0F0a5RL7sf36TYqs7wbYj7ZVZ/E1CrTOpe8UwpLIyGgUaIYSQbFeIFgOb/vXFwgeKQxGW811R5zpPBymWqmYlVplpLV2AM/rNGddq9HCllLqzT2nWCPVUnI8ZOQzCba8YsmO1yGnZUR3YRiLku7KiNc19+OVRBzFUaFlymYkoIHv+tONC5rAJoZg87Fgpz9BT1JVUjX31ZcrhPBcFCf3LCppBLfEeRcGlx0miOTprBmW+ebGmfutGaIwsxEknzE2uUuhEt/u5Vr54TWOAFFj8zNoY1mHi0updzMpX1//Pyb/BQ==&RelayState=TLOJ0uYURe3U9oDXLqN-7mAYtiu9rMvm&SigAlg=http://www.w3.org/2001/04/xmldsig-more#rsa-sha256&Signature=zoh6OlNvORipYvpT7+stuWhJHU2BZqHCVKBv38A9udHXoTdze+bSknGo+k497LvHklINvJ+BIbFJXKqUOP8+e/OE+k/tunUmfxeNKSwu+NuI2fuf3D4fsSjgO5ewEeZVGEc8xhQoUoTUHIns4LYG/BMObFowQq4twlZXQlwzuqUujjT4O3s9M9+hFm9MUCC6rLGYuETS1yNeDzgwGTtBCPvtuYKSvJ1pbkfxwJ4kbdCdpQZiL5tck2BffqzLMvbeghbAwT+igDaTI/wSSuc2oeTdwqnO05+Eb0BrRwTTfVbxWl6ttUuK6a0+WRqVB35HGDykKlXI39DO/6hEOeHmoQ==",
                    Query = new NameValueCollection()
                };

                req.Query.Add(Saml2Constants.Message.SamlRequest, "fZFNb4MwDIbP+xcod0agFIoFSJ16WKVNqjq0wy5TCAEiQcLisLX/fnzs0F0a5RL7sf36TYqs7wbYj7ZVZ/E1CrTOpe8UwpLIyGgUaIYSQbFeIFgOb/vXFwgeKQxGW811R5zpPBymWqmYlVplpLV2AM/rNGddq9HCllLqzT2nWCPVUnI8ZOQzCba8YsmO1yGnZUR3YRiLku7KiNc19+OVRBzFUaFlymYkoIHv+tONC5rAJoZg87Fgpz9BT1JVUjX31ZcrhPBcFCf3LCppBLfEeRcGlx0miOTprBmW+ebGmfutGaIwsxEknzE2uUuhEt/u5Vr54TWOAFFj8zNoY1mHi0updzMpX1//Pyb/BQ==");
                req.Query.Add(Saml2Constants.Message.RelayState, "TLOJ0uYURe3U9oDXLqN-7mAYtiu9rMvm");
                req.Query.Add("SigAlg", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
                req.Query.Add("Signature", "zoh6OlNvORipYvpT7+stuWhJHU2BZqHCVKBv38A9udHXoTdze+bSknGo+k497LvHklINvJ+BIbFJXKqUOP8+e/OE+k/tunUmfxeNKSwu+NuI2fuf3D4fsSjgO5ewEeZVGEc8xhQoUoTUHIns4LYG/BMObFowQq4twlZXQlwzuqUujjT4O3s9M9+hFm9MUCC6rLGYuETS1yNeDzgwGTtBCPvtuYKSvJ1pbkfxwJ4kbdCdpQZiL5tck2BffqzLMvbeghbAwT+igDaTI/wSSuc2oeTdwqnO05+Eb0BrRwTTfVbxWl6ttUuK6a0+WRqVB35HGDykKlXI39DO/6hEOeHmoQ==");

                return req;
            }
        }

        private Saml2Configuration Saml2Config
        {
            get
            {
                var opts = new Saml2Configuration()
                {
                    Issuer = "https://localhost:5003",
                    SingleSignOnDestination = new System.Uri("http://localhost:5000/saml/login"),
                    SingleLogoutDestination = new System.Uri("http://localhost:5000/saml/logout"),
                    SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                    SignAuthnRequest = true,
                    CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None,
                    RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck
                };

                opts.AllowedAudienceUris.Add("https://localhost:5003");

                return opts;
            }
        }
    }
}