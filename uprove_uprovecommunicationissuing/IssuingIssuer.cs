using System;
using System.Collections.Generic;
using System.Text;
using uprove_json;
using UProveCrypto;
using UProveCrypto.Math;

namespace uprove_uprovecommunicationissuing
{
    public class IssuingIssuer
    {
        #region Properties
        private Encoding encoding = Encoding.UTF8;
        private UProveJSONParser parser = new UProveJSONParser();
        private CommenIssuing ci = new CommenIssuing();

        private IssuerKeyAndParameters ikap;
        private FieldZqElement privateKey;
        private Issuer issuer;
        private bool isDeviceProtected;

        private List<BasicClaim> attributes;
        private List<string> rangeProofAttributes;
        #endregion Properties
        
        #region IssuingIssuer
        /// <summary>
        ///  This setup method initializes the issuer, do it once and save the IssuerParameters they were used for verifying the issuer later (Verifier / Prover)
        ///  and are used for initiate the issuer at another time
        /// </summary>
        /// <param name="UIDP">issuer identifier</param>
        /// <param name="appSpecification">description for the issuer</param>
        /// <param name="maxNumberOfAttributes">number of attributes which should be supported in a token -> max allowed attributes are 25</param>
        /// <param name="groupType">ECC or Subgroup</param>
        /// <param name="supportDevice">ture, if the issuer allows to protect a token with a hard tokens</param>
        public IssuingIssuer(string UIDP, string appSpecification, int maxNumberOfAttributes, 
            GroupType groupType = GroupType.ECC, bool supportDevice = false)
        {
            isDeviceProtected = supportDevice;
            try
            {
                // max allowed are 50 attributes
                if (maxNumberOfAttributes > 50)
                    throw new Exception("General supported are max 25 attributes");
            
                IssuerSetupParameters isp = new IssuerSetupParameters(maxNumberOfAttributes);
                isp.UidP = encoding.GetBytes(UIDP);
                isp.S = encoding.GetBytes(appSpecification);
                isp.GroupConstruction = groupType;
                isp.UseRecommendedParameterSet = true;

                ikap = isp.Generate(isDeviceProtected);

                privateKey = ikap.PrivateKey;
                string pk = privateKey.ToBase64String();
                string ipJSON = ikap.IssuerParameters.Serialize();
                LogService.Log(LogService.LogType.Info, "IssuingIssuer - successfully set up. IssuerParameters are: '" + ipJSON + "'");
            }
            catch (Exception e)
            {
                LogService.Log(LogService.LogType.FatalError, "IssuingIssuer - Error during issuer setup.", e);
                throw new CommunicationException("IssuingIssuer - Error during issuer setup", e);
            }
        }
        
        /// <summary>
        /// Initialize the issuer by json file (ip) and the privateKey
        /// </summary>
        /// <param name="jsonIP">issuerparameters from the issuer</param>
        /// <param name="privateKey">of the issuer to create valid tokens</param>
        public IssuingIssuer(string jsonIP, string privateKey)
        {
            ikap = new IssuerKeyAndParameters(privateKey, jsonIP);
            this.privateKey = ikap.PrivateKey;
            LogService.Log(LogService.LogType.Info, "IssuingIssuer - Issuer with given issuerparameter and private key initialized");
        }
        #endregion IssuingIssuer

        #region Init
        /// <summary>
        /// Initialize the parameters for the issuer, must be first called - before firstmessage is calculated
        /// </summary>
        /// <param name="attributes">Attributes which should be included in the token, number of attribute must be smaller than defined maxNumberOfAttributes</param>
        /// <param name="rangeProofAttributes">RangeProof attributes which should be included in the token, must be defined at this time</param>
        /// <param name="supportedDateAttributes">If there is a RangeProof done, all date attributes where treated and formated especially</param>
        public void Init(List<BasicClaim> attributes, List<string> rangeProofAttributes, List<string> supportedDateAttributes)
        {
            try
            {
                LogService.Log(LogService.LogType.Info, "IssuingIssuer - Init called");
                // check if number of attribute is lower than the max supported attributes
                // need to store the attribute descriptions too ( { "attributename" : "givenName", .. } ..
                if (attributes.Count * 2 > ikap.IssuerParameters.MaxNumberOfAttributes)
                    throw new Exception("Number of attributes is higher than the max number of supported attributes ("
                        + ikap.IssuerParameters.MaxNumberOfAttributes + ") by this issuer.");
                
                List<RangeProofProperties> rangeproofProperties;
                ci.CreateBase64ForAttributeList(attributes, supportedDateAttributes, out rangeproofProperties);
                this.attributes = attributes;
                this.rangeProofAttributes = rangeProofAttributes;
                byte[] e = GetE(attributes, (rangeProofAttributes != null));
                ikap.IssuerParameters.E = e;

                ikap = new IssuerKeyAndParameters(privateKey, new IssuerParameters(GetIssuerParameters()));
                LogService.Log(LogService.LogType.Info, "IssuingIssuer - Issuer for this prover initialized. " + attributes.Count + " attributes got included.");
            }
            catch(Exception e)
            {
                LogService.Log(LogService.LogType.FatalError, "IssuingIssuer - Error during init.", e);
                throw new CommunicationException("Error during issuer setup", e);
            }
        }
        #endregion Init
        
        #region GetIssuerParameters
        /// <summary>
        /// Important call the init method first / issuer must need to know the attributes
        /// </summary>
        /// <returns>Returns a JsonString with the IssuerParameters, could be shared with prover and verifier</returns>
        public string GetIssuerParameters()
        {
            if(ikap == null)
                throw new CommunicationException("IssuingIssuer - Issuer must first be initialized. Call init method first");
                
            IP ip = parser.ParseJsonToObject<IP>(ikap.IssuerParameters.Serialize());

            string expected = ikap.IssuerParameters.Serialize();
            string result = parser.ParseObjectToJson(ip);

            return parser.ParseObjectToJson(ip);
        }
        #endregion GetIssuerParameters

        #region GenerateFirstMessage
        /// <summary>
        /// creates the first message for the given number of tokens
        /// </summary>
        /// <param name="numberOfTokens">number of token to issue</param>
        /// <param name="ti">token information field</param>
        /// <param name="devicePublicKey">public key from the provers device</param>
        /// <returns>first message as json string</returns>
        public string GenerateFirstMessage(int numberOfTokens, byte[] ti = null, byte[] devicePublicKey = null)
        {            
            return GenerateFirstMessage(numberOfTokens, ti, (devicePublicKey != null ? ikap.IssuerParameters.Gq.CreateGroupElement(devicePublicKey) : null));
        }

        /// <summary>
        /// creates the first message for the given number of tokens
        /// </summary>
        /// <param name="numberOfTokens">number of token to issue</param>
        /// <param name="ti">token information field</param>
        /// <param name="devicePublicKey">public key from the provers device</param>
        /// <returns>first message as json string or if there was a failure, an empty string</returns>
        public string GenerateFirstMessage(int numberOfTokens, byte[] ti = null, GroupElement devicePublicKey = null)
        {
            try
            {
                LogService.Log(LogService.LogType.Info, "IssuingIssuer - GenerateFirstMessage called");

                IssuerProtocolParameters ipp = new IssuerProtocolParameters(ikap);
                ipp.Attributes = ci.ConvertAttributeListToBase64ByteArray(attributes);
                ipp.NumberOfTokens = numberOfTokens;
                ipp.TokenInformation = ti;

                // if it is device protected, device public key is needed here
                if (isDeviceProtected && devicePublicKey == null)
                    throw new Exception("DevicePublicKey is null. First message creation abort.");

                if (ipp.IssuerKeyAndParameters.IssuerParameters.IsDeviceSupported && devicePublicKey != null)
                    ipp.DevicePublicKey = devicePublicKey;

                issuer = ipp.CreateIssuer();
                // firstmessage for prover
                string firstMessageJson = ikap.IssuerParameters.Serialize<FirstIssuanceMessage>(
                    issuer.GenerateFirstMessage());
                
                LogService.Log(LogService.LogType.Info, "FirstMessage created: " + firstMessageJson);
                return firstMessageJson;
            }
            catch (Exception e)
            {
                LogService.Log(LogService.LogType.FatalError, "IssuingIssuer - Error during first message generation.", e);
                throw new CommunicationException("IssuingIssuer - Error during first message generation.", e);
            }
        }
        #endregion GenerateFirstMessage

        #region GenerateThirdMessage
        /// <summary>
        /// creates the third message out of the given second message
        /// </summary>
        /// <param name="secondMessageJson">json string from the second message</param>
        /// <returns>third message as json string or if there was a failure, an empty string</returns>
        public string GenerateThirdMessage(string secondMessageJson)
        {
            try
            {
                LogService.Log(LogService.LogType.Info, "IssuingIssuer - GenerateThirdMessage called");

                string thirdMessageJson = ikap.IssuerParameters.Serialize<ThirdIssuanceMessage>(issuer.GenerateThirdMessage(
                    ikap.IssuerParameters.Deserialize<SecondIssuanceMessage>(secondMessageJson)));

                LogService.Log(LogService.LogType.Info, "IssuingIssuer - ThirdMessage created: " + thirdMessageJson);
                return thirdMessageJson;
            }
            catch (Exception e)
            {
                LogService.Log(LogService.LogType.FatalError, "IssuingIssuer - Error during third message generation.", e);
                throw new CommunicationException("IssuingIssuer - Error during third message generation.", e);
            }
        }
        #endregion GenerateThirdMessage

        #region GetE
        /// <summary>
        /// Calculates the parameter e for the issuerparameter
        /// </summary>
        /// <param name="attributes">name and value are required</param>
        /// <param name="hasRangeProofAttributes">neccessary if prover wants to do a range proof, calculation of e is different</param>
        /// <returns>calculates value for parameter e</returns>
        private byte[] GetE(List<BasicClaim> attributes, bool hasRangeProofAttributes = false)
        {
            // need to store the attribute descriptions too ( { "attributename" : "givenName", .. } ..
            int numberOfAttributes = attributes.Count;
            byte[] e = new byte[numberOfAttributes * 2];

            if (numberOfAttributes == 0)
                return new byte[] { };

            if (hasRangeProofAttributes)
            {
                for (int i = 0; i < numberOfAttributes; i++)
                {
                    if (rangeProofAttributes.Contains(attributes[i].name))
                        e[i * 2] = 0; // 0 indicates that the attribute must be encoded directly (vs. hashed); this is needed for a range proof
                    else
                        e[i * 2] = 1;

                    // description is hashed every time (not possible to make a proof of it)
                    e[i * 2 + 1] = 1;
                }
            }
            else
            {
                for (int i = 0; i < numberOfAttributes; i++)
                {
                    e[i * 2] = 1;
                    e[i * 2 + 1] = 1;
                }
            }

            LogService.Log(LogService.LogType.Info, "Parameter e calculated: '" + e.ToString() + "'");
            return e;
        }
        #endregion GetE
    }
}
