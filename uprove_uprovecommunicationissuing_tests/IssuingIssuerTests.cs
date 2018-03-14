using Microsoft.VisualStudio.TestTools.UnitTesting;
using uprove_json;
using System.Collections.Generic;
using uprove_uprovecommunicationissuing;
using UProveCrypto;
using uprove_json.IssuerVerification;
using uprove_json.Proofs;
using uprove_json.VerifierAuthenticationCredentials;
using System.Text;

namespace uprove_uprovecommunicationissuing_tests
{
    [TestClass]
    public class IssuingIssuerTests
    {
        #region Properties
        private Encoding encoding = Encoding.UTF8;
        private UProveJSONParser parser = new UProveJSONParser();
        private TestHelper helper = new TestHelper();
        #endregion Properties
        
        #region MessagesTest
        [TestMethod]
        public void MessagesTest()
        {
            CommenIssuing ci = new CommenIssuing();

            List<BasicClaim> attributeWithKey = new List<BasicClaim>();
            attributeWithKey.Add(new BasicClaim() { name = "surname", values = new List<string>() { "Mustermann" }, qualitylevel = "loa2" });
            attributeWithKey.Add(new BasicClaim() { name = "givenName", values = new List<string>() { "Max" }, qualitylevel = "loa2" });
            attributeWithKey.Add(new BasicClaim() { name = "swissEduPersonHomeOrganization", values = new List<string>() { "BFH" }, qualitylevel = "loa3" });
            attributeWithKey.Add(new BasicClaim() { name = "swissEduPersonDateOfBirth", values = new List<string>() { "15.03.2003" }, qualitylevel = "loa2" });

            List<string> rangeProofAttributes = new List<string>() { "swissEduPersonDateOfBirth" };
            List<string> supportedDateAttributes = new List<string>() { "swissEduPersonDateOfBirth" };  // defines all range proof attributes which has a date as value

            int numberOfTokens = 2;
            byte[] ti = encoding.GetBytes("tiMessage");
            byte[] devicePublicKey = null;

            byte[] pi = encoding.GetBytes("piMessage");

            IssuerParameterWithPK expectedIP = parser.ParseJsonToObject<IssuerParameterWithPK>(helper.ReadFile("IssuerParameterWithPK"));
            // create issuer
            IssuingIssuer ii = new IssuingIssuer(parser.ParseObjectToJson(expectedIP.ip), expectedIP.privateKey);
            ii.Init(attributeWithKey, rangeProofAttributes, supportedDateAttributes);
            
            // check issuer parameters
            string ipJson = ii.GetIssuerParameters();
            IP ip = parser.ParseJsonToObject<IP>(ipJson);
            CheckIP(expectedIP.ip, ip);
            
            // Issuer create first message
            string firstMessageJson = ii.GenerateFirstMessage(numberOfTokens, ti, devicePublicKey);
            
            // create prover + second message
            IssuingProver isp = new IssuingProver();
            isp.Init(firstMessageJson, pi, attributeWithKey, numberOfTokens, ti, ipJson, supportedDateAttributes);

            string secondMessageJson = isp.GenerateSecondMessage(devicePublicKey);

            // issuer creates third message
            string thirdMessageJson = ii.GenerateThirdMessage(secondMessageJson);

            // prover creates token(s)
            isp.GenerateTokens(thirdMessageJson);
            UProveKeyAndToken[] ukats = isp.KeyAndToken;

            Assert.IsTrue(ukats.Length == numberOfTokens);

            // prover creates setmembership and range proof with the first token

            // setmembership requirements
            int commitmentIndexForSetMembershipProof = 5;
            List<VerifierMembers> verifiersMembers = new List<VerifierMembers>()
            {
                new VerifierMembers()
                {
                    Members = new List<string>() { "BFH", "ETH", "UniBern" },
                    verifiersSetMembershipProofId = 0,
                    MemberAttribute = "swissEduPersonHomeOrganization"
                }
            };


            // rangeproof requirements
            int commitmentIndexForRangeProof = 7;
            int[] commitmentIndexesForRangeProof = new int[] { commitmentIndexForRangeProof, commitmentIndexForRangeProof };

            ProofRequirements proofRequirements = new ProofRequirements()
            {
                committedAttributes = new int[] 
                {
                    commitmentIndexForSetMembershipProof    // contains the value BFH (for setmembership proof)
                    , commitmentIndexForRangeProof
                },
                disclosedAttributes = new int[] { 6, 8 },      // contains the values swissEduPersonHomeOrganization and swissEduPersonDateOfBirth
                message = encoding.GetBytes("messageMessage")
            };

            ProverProof pp = new ProverProof();
            // init the prover proof -> creates the initial proof
            string proofJson = pp.Init(isp.IP, attributeWithKey, proofRequirements, ukats[0], supportedDateAttributes, null);
            List<string> setMembershipProofJsons = pp.GenerateSetMembershipProofs(new int[] { commitmentIndexForSetMembershipProof }, verifiersMembers);

            // verifier verifys setmembership proof
            string trustedIssuersJson = helper.ReadFile("TrustedIssuerList");
            IssuingVerifier isv = new IssuingVerifier();
            isv.Init(ipJson, proofJson, parser.ParseObjectToJson(ukats[0].Token), trustedIssuersJson);
            bool isSetMembershipProof = isv.VerifySetMembershipProofs(setMembershipProofJsons, verifiersMembers);

            Assert.IsTrue(isSetMembershipProof);

            // create range proof
            List<VerifierRanges> vrs = new List<VerifierRanges>()   // given by verifier
            {
                new VerifierRanges()
                {
                    verifiersRangeProofId = 0,
                    rangeProofAttribute = "swissEduPersonDateOfBirth",
                    number = 14,
                    sibling = 1,
                    rangeProofType = RangeProofType.LESS_THAN_OR_EQUAL_TO.Value
                },
                new VerifierRanges()
                {
                    verifiersRangeProofId = 1,
                    rangeProofAttribute = "swissEduPersonDateOfBirth",
                    number = 18,
                    sibling = 0,
                    rangeProofType = RangeProofType.GREATER_THAN.Value
                }
            };
            
            List<VerifierRanges> verifierRangeProofToCommitmentIndexes = new List<VerifierRanges>();
            verifierRangeProofToCommitmentIndexes.Add(vrs[0]);
            verifierRangeProofToCommitmentIndexes.Add(vrs[1]);

            // prover generates range proofs
            List<string> rangeProofsJson = pp.GenerateRangeProofs(commitmentIndexesForRangeProof, verifierRangeProofToCommitmentIndexes);
            // verifier verifys the generated range proofs
            bool isRangeProof = isv.VerifyRangeProofs(rangeProofsJson, vrs);
            Assert.IsTrue(isRangeProof);
        }
        #endregion MessagesTest

        #region CheckIP
        private void CheckIP(IP expected, IP result)
        {
            Assert.AreEqual(expected.uidp, result.uidp);
            Assert.AreEqual(expected.uidh, result.uidh);
            Assert.AreEqual(expected.descGq.name, result.descGq.name);
            Assert.AreEqual(expected.descGq.type, result.descGq.type);
            Assert.AreEqual(expected.g.Count, result.g.Count);
            for (int i = 0; i < expected.g.Count; i++)
                Assert.AreEqual(expected.g[i], result.g[i]);
            //Assert.AreEqual(expected.e, result.e);    // not tested because it could change; dependent from attributes
            Assert.AreEqual(expected.s, result.s);
            Assert.AreEqual(expected.MaxNumberOfAttributes, result.MaxNumberOfAttributes);
        }
        #endregion CheckIP
    }
}
