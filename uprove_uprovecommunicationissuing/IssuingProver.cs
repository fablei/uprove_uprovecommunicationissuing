using System;
using System.Collections.Generic;
using System.Text;
using uprove_json;
using UProveCrypto;

namespace uprove_uprovecommunicationissuing
{
    public class IssuingProver
    {
        #region Properties
        private Encoding encoding = Encoding.UTF8;
        private UProveJSONParser parser = new UProveJSONParser();
        private CommenIssuing ci = new CommenIssuing();

        private string firstMessageJson;

        private byte[] ti;
        private byte[] pi;
        private int numberOfTokens;
        private Prover prover;

        // public readable properties
        public UProveKeyAndToken[] KeyAndToken { get; private set; }
        public IssuerParameters IP { get; private set; }
        public byte[][] ByteAttributes { get; private set; }
        public List<BasicClaim> Attributes { get; private set; }
        #endregion Properties

        #region Init
        /// <summary>
        /// Sets up the prover parameters with the ip, attributes, numberOfTokens, ti and the given pi
        /// for this token creation
        /// </summary>
        /// <param name="firstMessageJson">first message received from issuer, contains: ip, attributes, numberOfTokens, ti 
        /// and the first message itself</param>
        /// <param name="pi">prover information for the prover information field</param>
        /// <param name="attributes">attributes to insert into the tokens - chosen by the prover</param>
        /// <param name="numberOfTokens">number of tokens the prover wants to create</param>
        /// <param name="ti">token information field - given by the issuer</param>
        /// <param name="ipJson">issuer parameter - given by the issuer</param>
        public void Init(string firstMessageJson, byte[] pi, List<BasicClaim> attributes,
            int numberOfTokens, byte[] ti, string ipJson, List<string> supportedDateAttributes)
        {
            try
            {
                LogService.Log(LogService.LogType.Info, "IssuingProver - init called");

                this.firstMessageJson = firstMessageJson;
                this.pi = pi;

                List<RangeProofProperties> rangeProofProperties;
                ci.CreateBase64ForAttributeList(attributes, supportedDateAttributes, out rangeProofProperties);

                Attributes = attributes;
                this.numberOfTokens = numberOfTokens;
                this.ti = ti;

                // set issuer parameters
                IP = new IssuerParameters(ipJson);
                IP.Verify();
                LogService.Log(LogService.LogType.Info, "IssuingProver - Prover successfully set up");
            }
            catch (Exception e)
            {
                LogService.Log(LogService.LogType.FatalError, "IssuingProver - Error during prover setup.", e);
                throw new CommunicationException("IssuingProver - Error during prover setup.", e);
            }
        }
        #endregion Init

        #region GenerateSecondMessage
        /// <summary>
        /// creates the second message to the received first message from the issuer
        /// </summary>
        /// <param name="devicePublicKey">if it is hard token protected, the public key of that device</param>
        /// <returns>SecondMessage as json string</returns>
        public string GenerateSecondMessage(byte[] devicePublicKey = null)
        {
            return GenerateSecondMessage((devicePublicKey != null ? IP.Gq.CreateGroupElement(devicePublicKey) : null));
        }

        /// <summary>
        /// creates the second message to the received first message from the issuer
        /// </summary>
        /// <param name="devicePublicKey">if the tokens are hard token protected, this is
        /// the public key of that device</param>
        /// <returns>SecondMessage as json string or if there was a failure, an empty string</returns>
        public string GenerateSecondMessage(GroupElement devicePublicKey = null)
        {
            try
            {
                LogService.Log(LogService.LogType.Info, "IssuingProver - GenerateSecondMessage called");

                // initialize prover protocol
                ProverProtocolParameters ppp = new ProverProtocolParameters(IP);
                ppp.Attributes = ByteAttributes = ci.ConvertAttributeListToBase64ByteArray(Attributes);
                ppp.NumberOfTokens = numberOfTokens;

                ppp.TokenInformation = ti != null ? ti : null;
                ppp.ProverInformation = pi;

                if (devicePublicKey != null)
                    ppp.DevicePublicKey = devicePublicKey;

                prover = ppp.CreateProver();

                string secondMessageJson = IP.Serialize<SecondIssuanceMessage>(
                    prover.GenerateSecondMessage(IP.Deserialize<FirstIssuanceMessage>(firstMessageJson)));

                LogService.Log(LogService.LogType.Info, "IssuingProver - SecondMessage created: " + secondMessageJson);

                return secondMessageJson;
            }
            catch (Exception e)
            {
                LogService.Log(LogService.LogType.Error, "IssuingProver - Error during second message generation.", e);
                throw new CommunicationException("IssuingProver - Error during second message generation.", e);
            }
        }
        #endregion GenerateSecondMessage

        #region GenerateTokens
        /// <summary>
        /// Creates the token out of the received third message
        /// </summary>
        /// <param name="thirdMessage">third message as json</param>
        /// <param name="skipTokenValidation">if the hard token validation should get 
        /// skipped - testing mode only
        /// </param>
        public void GenerateTokens(string thirdMessage, bool skipTokenValidation = false)
        {
            try
            {
                LogService.Log(LogService.LogType.Info, "IssuingProver - GenerateTokens called");
                KeyAndToken = prover.GenerateTokens(IP.Deserialize<ThirdIssuanceMessage>(thirdMessage), skipTokenValidation);
                LogService.Log(LogService.LogType.Info, "IssuingProver - token successfull generated");
            }
            catch (Exception e)
            {
                LogService.Log(LogService.LogType.Info, "IssuingProver - Error during token generation.", e);
                throw new CommunicationException("IssuingProver - Error during token generation.", e);
            }
        }
        #endregion GenerateTokens
    }
}
