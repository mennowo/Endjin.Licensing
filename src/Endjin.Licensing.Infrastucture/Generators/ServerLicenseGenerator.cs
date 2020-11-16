namespace Endjin.Licensing.Infrastructure.Generators
{
    #region Using Directives

    using System;
    using System.Xml;
    using System.Security.Cryptography;
    using System.Security.Cryptography.Xml;
    using System.Text;

    using Endjin.Licensing.Contracts.Domain;
    using Endjin.Licensing.Domain;
    using Endjin.Licensing.Infrastructure.Contracts.Crypto;
    using Endjin.Licensing.Infrastructure.Contracts.Domain;
    using Endjin.Licensing.Infrastructure.Contracts.Generators;
    using Endjin.Licensing.Infrastructure.Domain;

    #endregion

    public sealed class ServerLicenseGenerator : IServerLicenseGenerator
    {
        public IServerLicense Generate(IPrivateCryptoKey privateKey, LicenseCriteria licenseCriteria, string elementKey = null)
        {
            var licenseDocument = this.CreateLicenseDocument(licenseCriteria);

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

                try
                {
                    foreach (var metaData in licenseCriteria.MetaData)
                    {
                        // Encrypt the metadata element.
                        Encrypt(licenseDocument, metaData.Key, rijndaelkey);
                    }

                    // Display the encrypted XML to the console.
                    //Console.WriteLine("Encrypted XML:");
                    //Console.WriteLine();
                    //Console.WriteLine(licenseDocument.OuterXml);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
                finally
                {
                    // Clear the TripleDES key.
                    rijndaelkey.Clear();
                }
            }

            var signature = LicenseSignatureGenerator.GenerateSignature(licenseDocument, privateKey);
            licenseDocument.FirstChild.AppendChild(licenseDocument.ImportNode(signature, true));

            return new ServerLicense
            {
                Content = licenseDocument, 
                Criteria = licenseCriteria,
                PrivateKey = privateKey,
                PublicKey = privateKey.ExtractPublicKey()
            };
        }

        private XmlDocument CreateLicenseDocument(LicenseCriteria licenseCriteria)
        {
            var licenseDocument = new XmlDocument();

            var licenseElement = licenseDocument.CreateElement(LicenseElements.License);
            licenseDocument.AppendChild(licenseElement);

            var id = licenseDocument.CreateElement(LicenseElements.Id);
            id.InnerText = licenseCriteria.Id.ToString();
            licenseElement.AppendChild(id);

            var expirationDate = licenseDocument.CreateElement(LicenseElements.ExpirationDate);
            expirationDate.InnerText = licenseCriteria.ExpirationDate.ToString("o");
            licenseElement.AppendChild(expirationDate);

            var issueDate = licenseDocument.CreateElement(LicenseElements.IssueDate);
            issueDate.InnerText = licenseCriteria.IssueDate.ToString("o");
            licenseElement.AppendChild(issueDate);

            var type = licenseDocument.CreateElement(LicenseElements.Type);
            type.InnerText = licenseCriteria.Type;
            licenseElement.AppendChild(type);

            foreach (var metaData in licenseCriteria.MetaData)
            {
                var element = licenseDocument.CreateElement(metaData.Key);
                element.InnerText = metaData.Value;
                licenseElement.AppendChild(element);
            }

            return licenseDocument;
        }

        private static void Encrypt(XmlDocument Doc, string ElementToEncrypt, SymmetricAlgorithm Alg)
        {
            // Check the arguments.  
            if (Doc == null)
                throw new ArgumentNullException(nameof(Doc));
            if (ElementToEncrypt == null)
                throw new ArgumentNullException(nameof(ElementToEncrypt));
            if (Alg == null)
                throw new ArgumentNullException(nameof(Alg));

            ////////////////////////////////////////////////
            // Find the specified element in the XmlDocument
            // object and create a new XmlElemnt object.
            ////////////////////////////////////////////////

            // Throw an XmlException if the element was not found.
            if (!(Doc.GetElementsByTagName(ElementToEncrypt)[0] is XmlElement elementToEncrypt))
            {
                throw new XmlException("The specified element was not found");

            }

            //////////////////////////////////////////////////
            // Create a new instance of the EncryptedXml class 
            // and use it to encrypt the XmlElement with the 
            // symmetric key.
            //////////////////////////////////////////////////

            var eXml = new EncryptedXml();

            var encryptedElement = eXml.EncryptData(elementToEncrypt, Alg, false);

            ////////////////////////////////////////////////
            // Construct an EncryptedData object and populate
            // it with the desired encryption information.
            ////////////////////////////////////////////////


            var edElement = new EncryptedData {Type = EncryptedXml.XmlEncElementUrl};

            // Create an EncryptionMethod element so that the 
            // receiver knows which algorithm to use for decryption.
            // Determine what kind of algorithm is being used and
            // supply the appropriate URL to the EncryptionMethod element.

            string encryptionMethod = null;

            if (Alg is TripleDES)
            {
                encryptionMethod = EncryptedXml.XmlEncTripleDESUrl;
            }
            else if (Alg is DES)
            {
                encryptionMethod = EncryptedXml.XmlEncDESUrl;
            }
            else if (Alg is Rijndael)
            {
                switch (Alg.KeySize)
                {
                    case 128:
                        encryptionMethod = EncryptedXml.XmlEncAES128Url;
                        break;
                    case 192:
                        encryptionMethod = EncryptedXml.XmlEncAES192Url;
                        break;
                    case 256:
                        encryptionMethod = EncryptedXml.XmlEncAES256Url;
                        break;
                }
            }
            else
            {
                // Throw an exception if the transform is not in the previous categories
                throw new CryptographicException("The specified algorithm is not supported for XML Encryption.");
            }

            edElement.EncryptionMethod = new EncryptionMethod(encryptionMethod);

            // Add the encrypted element data to the 
            // EncryptedData object.
            edElement.CipherData.CipherValue = encryptedElement;

            ////////////////////////////////////////////////////
            // Replace the element from the original XmlDocument
            // object with the EncryptedData element.
            ////////////////////////////////////////////////////

            EncryptedXml.ReplaceElement(elementToEncrypt, edElement, false);

        }
    }
}