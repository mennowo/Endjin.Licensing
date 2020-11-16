namespace Endjin.Licensing.Parsers
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
                SHA256CryptoServiceProvider hashSHA256 = new SHA256CryptoServiceProvider();
                byte[] keyArray = hashSHA256.ComputeHash(UTF8Encoding.UTF8.GetBytes(elementKey));

                //Always release the resources and flush data
                // of the Cryptographic service provide. Best Practice
                hashSHA256.Clear();

                // Create a new TripleDES key. 
                Rijndael Rijndaelkey = Rijndael.Create();

                Rijndaelkey.Key = keyArray;

                XmlDocument xdoc = clientLicense.Content;
                Decrypt(xdoc, Rijndaelkey);
                license = XDocument.Parse(xdoc.OuterXml).Root;
            }
            else
                license = XDocument.Parse(clientLicense.Content.OuterXml).Root;

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
                throw new ArgumentNullException("Doc");
            if (Alg == null)
                throw new ArgumentNullException("Alg");

            // Find the EncryptedData element in the XmlDocument.
            XmlElement encryptedElement = Doc.GetElementsByTagName("EncryptedData")[0] as XmlElement;

            // If the EncryptedData element was not found, throw an exception.
            if (encryptedElement == null)
            {
                throw new XmlException("The EncryptedData element was not found.");
            }

            // Create an EncryptedData object and populate it.
            EncryptedData edElement = new EncryptedData();
            edElement.LoadXml(encryptedElement);

            // Create a new EncryptedXml object.
            EncryptedXml exml = new EncryptedXml();

            // Decrypt the element using the symmetric key.
            byte[] rgbOutput = exml.DecryptData(edElement, Alg);

            // Replace the encryptedData element with the plaintext XML element.
            exml.ReplaceData(encryptedElement, rgbOutput);

        }

    }
}