using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using uprove_json;
using uprove_json.Proofs;
using uprove_json.VerifierAuthenticationCredentials;
using UProveCrypto;
using UProveCrypto.PolyProof;

namespace uprove_uprovecommunicationissuing
{
    /// <summary>
    /// Creates proofs (setmembership- or range proof) for the provers token - are used for authn. by the verifier
    /// </summary>
    public class ProverProof
    {
        #region Properties
        private Encoding encoding = Encoding.UTF8;
        private UProveJSONParser parser = new UProveJSONParser();
        private CommenIssuing ci = new CommenIssuing();

        private Proof proof;
        private ProverPresentationProtocolParameters pppp;
        private CommitmentPrivateValues cpv;
        private IssuerParameters ip;
        private ProofRequirements proofRequirements;
        private byte[][] attributesToInclude;
        List<RangeProofProperties> rangeProofProperties;
        #endregion Properties

        #region Init
        /// <summary>
        /// first method to call - Initializes the ProverProof by generating the PresentationProof
        /// </summary>
        /// <param name="ip">IssuerParameter from the Issuer of the given token</param>
        /// <param name="attributes">Attributes which are included in the given token</param>
        /// <param name="proofRequirements">Necessary informations for creating the proofs (e.g. disclosedAttributes)</param>
        /// <param name="tokenWithKey">Token for which the proof will be done</param>
        /// <param name="supportedDateAttributes">If there is a RangeProof done, all date attributes where treated and formated especially</param>
        /// <param name="devicePresentationContext">If there was a device involved during the token generation, the context from the device is needed to generate the 
        /// PresentationProof as well</param>
        /// <returns>returns the proof for the given token as json object or an error</returns>
        public string Init(IssuerParameters ip, List<BasicClaim> attributes, ProofRequirements proofRequirements,
            UProveKeyAndToken tokenWithKey, List<string> supportedDateAttributes, 
            IDevicePresentationContext devicePresentationContext)
        {
            try
            {
                LogService.Log(LogService.LogType.Info, "ProverProof - init called");
                this.ip = ip;
                this.proofRequirements = proofRequirements;
                ci.CreateBase64ForAttributeList(attributes, supportedDateAttributes, out rangeProofProperties);
                attributesToInclude = ci.ConvertAttributeListToBase64ByteArray(attributes);

                pppp = new ProverPresentationProtocolParameters(this.ip, proofRequirements.disclosedAttributes,
                    proofRequirements.message, tokenWithKey, attributesToInclude);
                pppp.Committed = proofRequirements.committedAttributes;

                //// TODO
                //// if a scope is defined, we use the first attribute to derive a scope exclusive pseudonym            
                //pppp.PseudonymAttributeIndex = (proofRequirements.scope == null ? 0 : 1);
                //pppp.PseudonymScope = proofRequirements.scope;

                // add device presentation context to the provers presentation context
                if (this.ip.IsDeviceSupported && devicePresentationContext != null)
                    pppp.SetDeviceData(proofRequirements.deviceMessage, devicePresentationContext);

                // generate proof 
                PresentationProof pProof = PresentationProof.Generate(pppp, out cpv);
                LogService.Log(LogService.LogType.Info, "ProverProof - init presentation proof generated");

                proof = parser.ParseJsonToObject<Proof>(this.ip.Serialize<PresentationProof>(pProof));
                proof.requirements = proofRequirements;

                string proofJson = parser.ParseObjectToJson(proof);
                LogService.Log(LogService.LogType.Info, "ProverProof - proof created: " + proofJson);

                return proofJson;
            }
            catch(Exception e)
            {
                LogService.Log(LogService.LogType.FatalError, "ProverProof - Error during prover setup.", e);
                throw new CommunicationException("ProverProof - Error during ProverProof init; " + e);
            }
        }
        #endregion Init

        #region GetProof
        /// <summary>
        /// Gets the proof (generated during the init process) of the used token
        /// </summary>
        /// <returns>proof from the given token as json or an empty string if there is no proof</returns>
        public string GetProof()
        {
            string proofJson = proof != null ? parser.ParseObjectToJson(proof) : string.Empty;
            LogService.Log(LogService.LogType.Info, "ProverProof - GetProof called: " + proofJson);
            return proofJson;
        }
        #endregion GetProof

        #region GenerateSetMembershipProofs
        /// <summary>
        /// Generates with the given commitment indexes in relation to the memberlist, a SetMembershipProof <br/>
        /// verifierSetMembershipProofToCommitmentIndexes[0] is used to create a setmembership proof with the commitmentIndexes[0] etc.
        /// </summary>
        /// <param name="commitmentIndexes">commitment attribute index for which the setmembership proof is (same index multiple time - allowed)</param>
        /// <param name="verifierSetMembershipProofToCommitmentIndexes">all setmembership proofs from the verifier which must be used</param>
        /// <returns>for all commitmentIndexes a setmembership proof</returns>
        public List<string> GenerateSetMembershipProofs(int[] commitmentIndexes, List<VerifierMembers> verifierSetMembershipProofToCommitmentIndexes)
        {
            try
            {
                LogService.Log(LogService.LogType.Info, "ProverProof - GenerateSetMembershipProofs called");

                // check same size
                if (commitmentIndexes.Length != verifierSetMembershipProofToCommitmentIndexes.Count)
                    throw new Exception("SetMembershipProofs and commitmentIndexes must have the same size.");

                List<string> setMembershipProofJsons = new List<string>();
                int commitmentIndex;

                for (int i = 0; i < commitmentIndexes.Length; i++)
                {
                    // check same attribute
                    commitmentIndex = Array.FindIndex<int>(pppp.Committed, x => x == commitmentIndexes[i]);
                    if (verifierSetMembershipProofToCommitmentIndexes[i].MemberAttribute !=
                        parser.ParseJsonToObject<BasicClaim>(encoding.GetString(Convert.FromBase64String(proof.D[commitmentIndex]))).name)
                        throw new Exception("Attribute name in defined VerifierRanges is not the same as in the presentation proof");

                    byte[][] memberList = ConvertStringListToByteArray(verifierSetMembershipProofToCommitmentIndexes[i].Members);

                    string setMembershipProofJson = GenerateSetMembershipProof(commitmentIndexes[i], memberList, 
                        verifierSetMembershipProofToCommitmentIndexes[i].verifiersSetMembershipProofId);
                    
                    LogService.Log(LogService.LogType.Info, "ProverProof - setmembership proof for memberlist ["
                        + verifierSetMembershipProofToCommitmentIndexes[i].verifiersSetMembershipProofId + "], created: " + setMembershipProofJson);
                    setMembershipProofJsons.Add(setMembershipProofJson);
                }

                return setMembershipProofJsons;
            }
            catch (Exception e)
            {
                LogService.Log(LogService.LogType.Error, "ProverProof - Error in GenerateSetMembershipProofs", e);
                throw new CommunicationException("ProverProof - Error in GenerateSetMembershipProofs", e);
            }
        }
        #endregion GenerateSetMembershipProofs

        #region GenerateRangeProofs
        /// <summary>
        /// Generates with the given committed indexes in relation to the verifier ranges a range proof <br/>
        /// verifierRangeProofToCommittedIndexes[0] is used to create a range proof with the committedIndexes[0] etc.
        /// </summary>
        /// <param name="committedIndexes">committed attribute index for which the range proof is (same index multiple time - allowed)</param>
        /// <param name="verifierRangeProofToCommittedIndexes">all range proofs from the verifier which must be used</param>
        /// <returns>for all committedIndexes a range proof</returns>
        public List<string> GenerateRangeProofs(int[] committedIndexes, List<VerifierRanges> verifierRangeProofToCommittedIndexes)
        {
            try
            {
                LogService.Log(LogService.LogType.Info, "ProverProof - GenerateRangeProofs called");

                if (committedIndexes.Length != verifierRangeProofToCommittedIndexes.Count)
                    throw new Exception("RangeProofTypes and committedIndexes must have the same size.");

                foreach (RangeProofProperties p in rangeProofProperties)
                {
                    if (ip.E[p.Index - 1] != 0) // rangeProofIndex - 1 => where the value of the date is stored
                        throw new Exception("DOB attribute must be encoded directly in order to create a range proof");
                }

                List<string> rangeProofs = new List<string>();

                int minYear = 0;
                int maxYear = 0;
                int commitmentIndex;

                for(int i = 0; i < committedIndexes.Length; i++)
                {
                    RangeProofProperties p = rangeProofProperties
                        .Where(x => x.AttributeName == parser.ParseJsonToObject<BasicClaim>(encoding.GetString(
                            attributesToInclude[committedIndexes[i]])).name)
                        .First<RangeProofProperties>();

                    minYear = p.MinYear;
                    maxYear = p.MaxYear;
                    commitmentIndex = Array.FindIndex<int>(pppp.Committed, x => x == p.Index);

                    // check if range proof attributes is the same as in the properties
                    if (verifierRangeProofToCommittedIndexes[i].rangeProofAttribute != 
                        parser.ParseJsonToObject<BasicClaim>(encoding.GetString(Convert.FromBase64String(proof.D[commitmentIndex]))).name)
                        throw new Exception("Attribute name in defined VerifierRanges is not the same as in the presentation proof");

                    // create range proof now
                    DateTime dateToVerify = DateTime.Today.AddYears(-verifierRangeProofToCommittedIndexes[i].number);

                    string rangeProofJson = GenerateRangeProof(commitmentIndex, RangeProofType.GetType(verifierRangeProofToCommittedIndexes[i].rangeProofType), 
                        dateToVerify, minYear, maxYear, verifierRangeProofToCommittedIndexes[i].verifiersRangeProofId);

                    LogService.Log(LogService.LogType.Info, "ProverProof - range proof for verifiersRange ["
                        + verifierRangeProofToCommittedIndexes[i].verifiersRangeProofId + "], created: " + rangeProofJson);
                    rangeProofs.Add(rangeProofJson);
                }

                LogService.Log(LogService.LogType.Info, "ProverProof - all range proofs are generated");
                return rangeProofs;
            }
            catch (Exception e)
            {
                LogService.Log(LogService.LogType.Error, "ProverProof - Error in GenerateRangeProofs", e);
                throw new CommunicationException("ProverProof - Error in GererateRangeProofs", e);
            }
        }
        #endregion GenerateRangeProofs

        #region ConvertStringListToByteArray
        /// <summary>
        /// Converts a given string list to a byte array
        /// </summary>
        /// <param name="stringList">list to convert</param>
        /// <returns>Returns the byte from the converted list</returns>
        private byte[][] ConvertStringListToByteArray(List<string> stringList)
        {
            byte[][] byteArray = new byte[stringList.Count][];
            for (int i = 0; i < stringList.Count; i++)
                byteArray[i] = encoding.GetBytes(stringList[i]);

            return byteArray;
        }
        #endregion ConvertStringListToByteArray

        #region GenerateRangeProof
        /// <summary>
        /// Generates one range proof with the given parameters
        /// </summary>
        /// <param name="commitmentIndex">commitmentIndex of the attribute, used for the range proof</param>
        /// <param name="rangeProofType">used range proof type</param>
        /// <param name="dateToVerify"></param>
        /// <param name="minYear">min reference year</param>
        /// <param name="maxYear">max reference year</param>
        /// <param name="verifiersRangeProofId">id from the verifiers published range proof properties</param>
        /// <returns>returns a json string which contains the range proof</returns>
        private string GenerateRangeProof(int commitmentIndex, RangeProofType rangeProofType, DateTime dateToVerify,
            int minYear, int maxYear, int verifiersRangeProofId)
        {
            uprove_json.Proofs.RangeProof rangeProof = parser.ParseJsonToObject<uprove_json.Proofs.RangeProof>(
                        ip.Serialize<UProveCrypto.PolyProof.RangeProof>(new UProveCrypto.PolyProof.RangeProof(
                        RangeProofParameterFactory.GetDateTimeProverParameters(
                                      new CryptoParameters(ip),
                                      new PedersenCommitment(pppp, ip.Deserialize<PresentationProof>(parser.ParseObjectToJson(proof)),
                                        cpv, commitmentIndex),
                                      rangeProofType.ProofType,
                                      dateToVerify,
                                      minYear,
                                      maxYear))));

            rangeProof.minBirthYear = minYear;
            rangeProof.maxBirthYear = maxYear;
            rangeProof.rangeProofType = rangeProofType.Value;
            rangeProof.verifiersRangeProofId = verifiersRangeProofId;
            rangeProof.targetDate = dateToVerify.ToString();
            rangeProof.commitmentIndex = commitmentIndex;

            return parser.ParseObjectToJson(rangeProof);
        }
        #endregion GenerateRangeProof

        #region GenerateSetMembershipProof
        /// <summary>
        /// Generates a setmembership proof with the given parameters
        /// </summary>
        /// <param name="commitmentIndex">commitment index of the used attribute</param>
        /// <param name="memberList">member list in which the attribute value is in</param>
        /// <param name="verifiersSetMembershipProofId">id from the verifiers published setmembership proof properties</param>
        /// <returns>returns a json string which contains a setmembership proof</returns>
        private string GenerateSetMembershipProof(int commitmentIndex, byte[][] memberList, int verifiersSetMembershipProofId)
        {
            // generate membership proof and add properties needed for verification
            uprove_json.Proofs.SetMembershipProof setMembershipProof = parser.ParseJsonToObject<uprove_json.Proofs.SetMembershipProof>(
                ip.Serialize<UProveCrypto.PolyProof.SetMembershipProof>(UProveCrypto.PolyProof.SetMembershipProof.Generate(pppp,
                ip.Deserialize<PresentationProof>(parser.ParseObjectToJson(proof)), cpv, commitmentIndex, memberList)));
            setMembershipProof.setValues = memberList;
            setMembershipProof.verifiersSetMembershipProofId = verifiersSetMembershipProofId;
            setMembershipProof.commitmentIndex = commitmentIndex;

            return parser.ParseObjectToJson(setMembershipProof);
        }
        #endregion GenerateSetMembershipProof
    }
}
