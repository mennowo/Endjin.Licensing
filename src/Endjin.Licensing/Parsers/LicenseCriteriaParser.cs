﻿namespace Endjin.Licensing.Parsers
{
    #region Using Directives

    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.Xml;
    using System.Text;
    using System.Xml;
    using System.Xml.Linq;

    using Endjin.Licensing.Contracts.Domain;
    using Endjin.Licensing.Contracts.Parsers;
    using Endjin.Licensing.Domain;

    #endregion

    public sealed class LicenseCriteriaParser : ILicenseCriteriaParser
    {
        public LicenseCriteria Parse(IClientLicense clientLicense, string elementKey = null)
        {
            XElement license;

            if (!string.IsNullOrEmpty(elementKey))
            {
                var hashSha256 = new SHA256CryptoServiceProvider();
                var keyArray = hashSha256.ComputeHash(Encoding.UTF8.GetBytes(elementKey));

                //Always release the resources and flush data
                // of the Cryptographic service provide. Best Practice
                hashSha256.Clear();

                // Create a new TripleDES key. 
                var rijndaelkey = Rijndael.Create();

                rijndaelkey.Key = keyArray;

                var xdoc = clientLicense.Content;
                Decrypt(xdoc, rijndaelkey);
                license = XDocument.Parse(xdoc.OuterXml).Root;
            }
            else
                license = XDocument.Parse(clientLicense.Content.OuterXml).Root;

            if (license == null) throw new FormatException("Could not parse XML document");

            var licenseDetails = license.Elements()
                .Where(element => element.Name.LocalName != LicenseElements.Signature)
                .Select(element => new KeyValuePair<string, string>(element.Name.LocalName, element.Value))
                .ToDictionary(pair => pair.Key, pair => pair.Value);

            var licenseCriteria = new LicenseCriteria
            {
                ExpirationDate = DateTimeOffset.Parse(licenseDetails[LicenseElements.ExpirationDate]),
                IssueDate = DateTimeOffset.Parse(licenseDetails[LicenseElements.IssueDate]),
                Id = Guid.Parse(licenseDetails[LicenseElements.Id]),
                Type = licenseDetails[LicenseElements.Type]
            };

            licenseDetails.Remove(LicenseElements.ExpirationDate);
            licenseDetails.Remove(LicenseElements.Id);
            licenseDetails.Remove(LicenseElements.IssueDate);
            licenseDetails.Remove(LicenseElements.Type);

            licenseCriteria.MetaData = licenseDetails;

            return licenseCriteria;

        }

        private static void Decrypt(XmlDocument Doc, SymmetricAlgorithm Alg)
        {
            // Check the arguments.  
            if (Doc == null)
                throw new ArgumentNullException(nameof(Doc));
            if (Alg == null)
                throw new ArgumentNullException(nameof(Alg));

            // Find the EncryptedData element in the XmlDocument.
            var encryptedElement = Doc.GetElementsByTagName("EncryptedData")[0] as XmlElement;

            // If the EncryptedData element was not found, throw an exception.
            if (encryptedElement == null)
            {
                throw new XmlException("The EncryptedData element was not found.");
            }

            // Create an EncryptedData object and populate it.
            var edElement = new EncryptedData();
            edElement.LoadXml(encryptedElement);

            // Create a new EncryptedXml object.
            var exml = new EncryptedXml();

            // Decrypt the element using the symmetric key.
            var rgbOutput = exml.DecryptData(edElement, Alg);

            // Replace the encryptedData element with the plaintext XML element.
            exml.ReplaceData(encryptedElement, rgbOutput);

        }

    }
}