using System;
using System.Collections.Generic;
using System.Linq;
using uprove_json;
using uprove_json.Proofs;
using UProveCrypto;
using uprove_json.VerifierAuthenticationCredentials;
using UProveCrypto.PolyProof;
using uprove_json.IssuerVerification;

namespace uprove_uprovecommunicationissuing
{
    public class IssuingVerifier
    {
        #region Properties
        private IssuerParameters IP;
        private PresentationProof pProof;
        private VerifierPresentationProtocolParameters vppp;
        private bool isInitialized;
        private string trustedIssuerJson;
        private string proofJson;
        private string tokenJson;
        private bool proofAccepted;
        private bool tokenAccepted;
        private ProofRequirements proofRequirements;

        private UProveJSONParser parser = new UProveJSONParser();
        private System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();
        #endregion Properties

        #region Init
        /// <summary>
        /// Initialise the system for a given token by the prover
        /// </summary>
        /// <param name="ipJson">Json string of the issuer parameters which has issued the given token</param>
        /// <param name="proofJson">Json string that includes the proof to the given token and later proofs - 
        /// created by the prover itself</param>
        /// <param name="tokenJson">Json of the token - created by issuer and prover</param>
        /// <param name="trustedIssuerJson">List of trusted issuers; in IP format, could be more than one Issuer 
        /// in a anonymus Json-Object; { "IP..</param>
        public void Init(string ipJson, string proofJson, string tokenJson, string trustedIssuerJson)
        {
            LogService.Log(LogService.LogType.Info, "IssuingVerifier - init called");

            proofAccepted = false;
            tokenAccepted = false;
            isInitialized = false;

            // create issuer parameters
            IP = new IssuerParameters(ipJson);
            IP.Verify();

            this.trustedIssuerJson = trustedIssuerJson;
            CheckTrustedIssuer();
            
            Proof proof = parser.ParseJsonToObject<Proof>(proofJson);
            proofRequirements = proof.requirements;

            PresentationProof pProof = IP.Deserialize<PresentationProof>(proofJson);
                        
            this.tokenJson = tokenJson;
            this.proofJson = IP.Serialize(pProof);            

            isInitialized = true;
            LogService.Log(LogService.LogType.Info, "IssuingVerifier - successfully initialized");

            VerifyProof();
        }
        #endregion Init

        #region VerifySetMembershipProofs
        /// <summary>
        /// Init must be called first
        /// Checks if the given setmembership proofs were correct - to the token and proof (given in the init method)
        /// </summary>
        /// <param name="setMembershipProofJsons">List of setmemberships proofs to check</param>
        /// <param name="verifierMembers">List of members, in which the setmembership proof has to be (given by the verifier)
        /// e.g setMembershipProofJsons[x] must include members from verifierMembers[x]
        /// </param>
        /// <returns>true --> all membership proof were successfull; exception -> something went wrong</returns>
        public bool VerifySetMembershipProofs(List<string> setMembershipProofJsons, List<VerifierMembers> verifierMembers)
        {
            try
            {
                LogService.Log(LogService.LogType.Info, "IssuingVerifier - VerifySetMembershipProofs called");

                if (!isInitialized || !proofAccepted || !tokenAccepted)
                    throw new Exception("SetMembershipProof could not be proved; isInitialized:" + isInitialized
                        + ", Proof verifierd:" + proofAccepted + ", Token verified:" + tokenAccepted);
                
                Proof proof = parser.ParseJsonToObject<Proof>(proofJson);
                uprove_json.Proofs.SetMembershipProof smp;
                VerifierMembers vm;
                int commitmentIndex;

                foreach (string oneSetMembershipProof in setMembershipProofJsons)
                {
                    LogService.Log(LogService.LogType.Info, "IssuingVerifier - SetMembershipProof given: " + oneSetMembershipProof);

                    smp = parser.ParseJsonToObject<uprove_json.Proofs.SetMembershipProof>(oneSetMembershipProof);
                    vm = verifierMembers.Where(x => x.verifiersSetMembershipProofId == smp.verifiersSetMembershipProofId).FirstOrDefault<VerifierMembers>();

                    // check if there was a verifier ranges object found
                    if (vm == null)
                        throw new Exception("No such proof given");

                    commitmentIndex = Array.FindIndex<int>(proofRequirements.committedAttributes, x => x == smp.commitmentIndex);
                    // attribute == commitment attribute
                    if (parser.ParseJsonToObject<BasicClaim>(encoding.GetString(Convert.FromBase64String(proof.D[commitmentIndex]))).name
                        != vm.MemberAttribute)
                        throw new Exception("Attribute commitment is not matching attribute from verifiers setmembership proof properties");

                    // check proof itself
                    UProveCrypto.PolyProof.SetMembershipProof setProof = IP.Deserialize<UProveCrypto.PolyProof.SetMembershipProof>(oneSetMembershipProof);

                    if (!UProveCrypto.PolyProof.SetMembershipProof.Verify(vppp, pProof, setProof, smp.commitmentIndex, smp.setValues))
                        throw new Exception("SetMembership Proof failed.");
                    else
                        // check if it is a member of the allowed universities
                        CheckIfMemberOfAllowedMembers(vm.Members, smp.setValues);

                    LogService.Log(LogService.LogType.Info, "IssuingVerifier - SetMembershipProof passed tests");
                }

                LogService.Log(LogService.LogType.Info, "IssuingVerifier - All setMembershipProofs passed tests");
                return true;                
            }
            catch (Exception e)
            {
                LogService.Log(LogService.LogType.FatalError, "IssuingVerifier - VerifySetMembershipProof failed.", e);
                throw new CommunicationException("IssuingVerifier - VerifySetMembershipProof failed.", e);
            }
        }


        ///// <summary>
        ///// Init must be called first
        ///// Checks if the given setmembership proofs were correct - compare with the given setmembership proof settings from the verifier
        ///// <returns>true --> all membership proof were successfull; exception -> something went wrong</returns>
        ///// </summary>
        //public bool VerifySetMembershipProofs(string setMembershipProofJson, VerifierMembers memberList)
        //{
        //    try
        //    {
        //        LogService.Log(LogService.LogType.Info, "IssuingVerifier - VerifySetMembershipProofs called");

        //        proofVerification.IsMemberOf = memberList.Members;
        //        VerifyProof();

        //        if (!isInitialized || !proofAccepted || !tokenAccepted)
        //            throw new Exception("SetMembershipProof could not be proved; isInitialized:" + isInitialized
        //                + ", Proof verifierd:" + proofAccepted + ", Token verified:" + tokenAccepted);

        //        LogService.Log(LogService.LogType.Info, "IssuingVerifier - SetMembershipProof given: " + setMembershipProofJson);
        //        bool canContinue = false;
        //        Proof proof = parser.ParseJsonToObject<Proof>(proofJson);

        //        // check if the disclosed attribute is from the expected type (name) and disclosed -1 = committedAttribute
        //        for (int i = 0; i < proof.D.Count; i++)
        //        {
        //            // check if the name of the attribute is like the given member attribute name
        //            if (memberList.MemberAttribute ==
        //                parser.ParseJsonToObject<BasicClaim>(encoding.GetString(Convert.FromBase64String(proof.D[i]))).name)
        //            {
        //                if (proofRequirements.committedAttributes.Contains(proofRequirements.disclosedAttributes[i] - 1))
        //                {
        //                    canContinue = true;
        //                    LogService.Log(LogService.LogType.Info, "IssuingVerifier - Given SetMembership attribute name matches defined attribute name");
        //                    break;
        //                }
        //            }
        //        }

        //        if (!canContinue)
        //            throw new Exception("Given SetMembership attribute name does not matches the expected attribute name '" + memberList.MemberAttribute + "'. ");

        //        byte[][] setValues = parser.ParseJsonToObject<uprove_json.Proofs.SetMembershipProof>(setMembershipProofJson).setValues;
        //        int commitmentIndex = parser.ParseJsonToObject<uprove_json.Proofs.SetMembershipProof>(setMembershipProofJson).commitmentIndex;
        //        UProveCrypto.PolyProof.SetMembershipProof setProof = IP.Deserialize<UProveCrypto.PolyProof.SetMembershipProof>(setMembershipProofJson);

        //        if (!UProveCrypto.PolyProof.SetMembershipProof.Verify(vppp, pProof, setProof, commitmentIndex, setValues))
        //            throw new Exception("SetMembership Proof failed.");
        //        else
        //            // check if it is a member of the allowed universities
        //            return CheckIfMemberOfAllowedMembers(setValues);
        //    }
        //    catch (Exception e)
        //    {
        //        LogService.Log(LogService.LogType.FatalError, "IssuingVerifier - VerifySetMembershipProof failed.", e);
        //        throw new CommunicationException("IssuingVerifier - VerifySetMembershipProof failed.", e);
        //    }
        //}
        #endregion VerifySetMembershipProofs

        #region VerifyRangeProofs
        /// <summary>
        /// Init must called first
        /// Checks if the given range proofs were correct - compare with the given range proof settings from the verifier
        /// </summary>
        /// <param name="rangeProofJsons">list of range proofs to check and verify</param>
        /// <param name="verifierRanges">list of range proofs settings - given by the verifier
        /// e.g. rangeProofJsons[x] must include settings from verifierRanges[x]</param>
        /// <returns>true -> all range proofs were successfull, exception -> something went wrong</returns>
        public bool VerifyRangeProofs(List<string> rangeProofJsons, List<VerifierRanges> verifierRanges)
        {
            try
            {
                LogService.Log(LogService.LogType.Info, "IssuingVerifier - VerifyRangeProofs called");

                if (!isInitialized || !proofAccepted || !tokenAccepted)
                    throw new Exception("VerifyRangeProofs could not be proved; isInitialized:" + isInitialized
                        + ", Proof verifierd:" + proofAccepted + ", Token verified:" + tokenAccepted);

                int[] rangeProofAttributeMatch = new int[2];
                List<int> committedAttributes = proofRequirements.committedAttributes.Select(id => id).ToList<int>();
                List<int> disclosedAttributes = proofRequirements.disclosedAttributes.Select(id => id).ToList<int>();

                // check if the disclosed attribute is from the expected type (name) and disclosed -1 = committedAttribute
                Proof proof = parser.ParseJsonToObject<Proof>(proofJson);
                                
                if (rangeProofAttributeMatch[0] != rangeProofAttributeMatch[1])
                    throw new Exception("Given range proof attribute name does not matches the expected attribute name '"
                        + "todo display range proof attributes" + "'. ");

                uprove_json.Proofs.RangeProof rp;
                VerifierRanges vr;
                List<VerifierRanges> testedVRs = new List<VerifierRanges>();

                foreach (string oneRangeProofJson in rangeProofJsons)
                {
                    LogService.Log(LogService.LogType.Info, "IssuingVerifier - RangeProof given: " + oneRangeProofJson);
                    rp = parser.ParseJsonToObject<uprove_json.Proofs.RangeProof>(oneRangeProofJson);
                    vr = verifierRanges.Where(x => x.verifiersRangeProofId == rp.verifiersRangeProofId).FirstOrDefault<VerifierRanges>();

                    // check if there was a verifier ranges object found
                    if (vr == null)
                        throw new Exception("No such proof given");

                    // set this proof as tested -> check later if sibling got tested too
                    testedVRs.Add(vr);

                    // attribute == commitment attribute
                    if (parser.ParseJsonToObject<BasicClaim>(encoding.GetString(Convert.FromBase64String(proof.D[rp.commitmentIndex]))).name
                        != vr.rangeProofAttribute)
                        throw new Exception("Attribute commitment is not matching attribute from verifiers range proof properties");

                    // rangeProofType == rangeProofType
                    if (rp.rangeProofType != vr.rangeProofType)
                        throw new Exception("Proof type is not matching proof tpye from verifiers range proof properties");

                    // check if target date is correct set and then check if the proof is correct
                    if (!(DateTime.Compare(Convert.ToDateTime(rp.targetDate), DateTime.Now.AddYears(-vr.number)) <= 0))
                        throw new Exception("TargetDate is in the wrong format (to small or large).");

                    // check range proof
                    UProveCrypto.PolyProof.RangeProof vRangeProof = IP.Deserialize<UProveCrypto.PolyProof.RangeProof>(oneRangeProofJson);

                    // and verify the range proof
                    if (!vRangeProof.Verify(
                        RangeProofParameterFactory.GetDateTimeVerifierParameters(
                            new CryptoParameters(IP),
                            new ClosedPedersenCommitment(IP, pProof, rp.commitmentIndex).Value,
                            //(VerifierRangeProofParameters.ProofType)
                            RangeProofType.GetType(rp.rangeProofType).ProofType,
                            Convert.ToDateTime(rp.targetDate),
                            rp.minBirthYear,
                            rp.maxBirthYear)))
                    {
                        throw new Exception("RangeProof failed");
                    }
                    LogService.Log(LogService.LogType.Info, "IssuingVerifier - RangeProof passed tests");
                }

                // check siblings
                CheckSiblings(testedVRs);
                
                return true;
            }
            catch (Exception e)
            {
                LogService.Log(LogService.LogType.FatalError, "IssuingVerifier - Verifing range proof failed.", e);
                throw new CommunicationException("IssuingVerifier - Verifing range proof failed.", e);
            }
        }
        #endregion VerifyRangeProofs

        #region CheckSiblings
        /// <summary>
        /// Checks if sibling was tested as well (has sibling -> sibling >= 0)
        /// </summary>
        /// <param name="testedVRs">VerifierRanges to check if sibling is inside that list as well</param>
        private void CheckSiblings(List<VerifierRanges> testedVRs)
        {
            LogService.Log(LogService.LogType.Info, "IssuingVerifier - CheckSiblings called");

            foreach (VerifierRanges vrs in testedVRs)
            {
                if (vrs.sibling >= 0
                    && testedVRs.Where(x => x.verifiersRangeProofId == vrs.sibling)
                        .FirstOrDefault<VerifierRanges>() == null)
                    throw new Exception("Range proof failed - sibling was not tested");
            }
            LogService.Log(LogService.LogType.Info, "IssuingVerifier - CheckSiblings are all good");
        }
        #endregion CheckSiblings

        #region CheckIfMemberOfAllowedMembers
        /// <summary>
        /// Checks if the given member array is part of the allowed members (e.g. universities)
        /// </summary>
        /// <param name="referenceMemberList">Contains the member list, given by the verifier</param>
        /// <param name="memberArray">The provided members (e.g. universities)</param>
        /// <returns>true --> contains all members from the given array, false --> not in the list</returns>
        private bool CheckIfMemberOfAllowedMembers(List<string> referenceMemberList, byte[][] memberArray)
        {
            LogService.Log(LogService.LogType.Info, "IssuingVerifier - CheckIfMemberOfAllowedMembers called");
            if (referenceMemberList == null || referenceMemberList.Count == 0)
                throw new Exception("referenceMemberList is null or empty");

            List<string> memberList = new List<string>();

            for (int i = 0; i < memberArray.Length; i++)
                memberList.Add(encoding.GetString(memberArray[i]));

            // check if elements are the same
            foreach (string member in memberList)
            {
                if (!referenceMemberList.Contains(member))
                    throw new Exception("SetMembership attribute '" + member + "' is not in the memberlist");
            }
            return true;
        }
        #endregion CheckIfMemberOfAllowedMembers

        #region CheckTrustedIssuer
        /// <summary>
        /// Checks if there exists an issuer in the trusted issuer list, with the given parameters <br/>
        /// if there does not exists an issuer in the list or the properties do not match, an error gets thrown
        /// </summary>
        private void CheckTrustedIssuer()
        {
            LogService.Log(LogService.LogType.Info, "IssuingVerifier - CheckTrustedIssuer called");
            TrustedIssuerList trustedIssuers = parser.ParseJsonToObject<TrustedIssuerList>(trustedIssuerJson);
            
            foreach (IP trustedIP in trustedIssuers.issuers)
            {
                // uidp must be equals otherwise it is not the same issuer
                if (trustedIP.uidp == IP.UidP.ToBase64String())
                {
                    if (trustedIP.g[0] != IP.G[0].ToBase64String())
                        throw new Exception("Issuer has the same UidP '" + trustedIP.uidp + "', but different g0");
                    if (trustedIP.uidh != IP.UidH)
                        throw new Exception("TrustedIssuer - UidH not equals");
                    if (trustedIP.s != IP.S.ToBase64String())
                        throw new Exception("TrustedIssuer - S not equals");
                    if (trustedIP.MaxNumberOfAttributes != IP.MaxNumberOfAttributes)
                        throw new Exception("TrustedIssuer - MaxNumberOfAttributes not equals");
                    if (trustedIP.descGq.name != IP.Gq.GroupName)
                        throw new Exception("TrustedIssuer - GroupName not equals");

                    LogService.Log(LogService.LogType.Info, "IssuingVerifier - Issuer found and passed tests");
                    return;
                }
            }
            throw new Exception("Given issuer is not in the trusted list");
        }
        #endregion CheckTrustedIssuer

        #region VerifyProof
        /// <summary>
        /// Verifies if the given json message has sent a correct proof
        /// the result is written into proofVerification.Proof
        /// Init must called first
        /// </summary>
        private void VerifyProof()
        {
            LogService.Log(LogService.LogType.Info, "IssuingVerifier - VerifyProof called");
            if (!isInitialized)
            {
                proofAccepted = false;
                tokenAccepted = false;
                throw new Exception("VerifyProof - Init must be called first");
            }

            int[] disclosedAttributes = proofRequirements.disclosedAttributes;
            int[] committedAttributes = proofRequirements.committedAttributes;
            byte[] message = proofRequirements.message;
            byte[] scope = proofRequirements.scope;
            byte[] deviceMessage = proofRequirements.deviceMessage;

            vppp = new VerifierPresentationProtocolParameters(IP, disclosedAttributes, message, IP.Deserialize<UProveToken>(tokenJson));
            vppp.Committed = committedAttributes;
            // if a scope is defined, we use the first attribute to derive a scope exclusive pseudonym            
            vppp.PseudonymAttributeIndex = (scope == null ? 0 : 1);
            vppp.PseudonymScope = scope;
            vppp.DeviceMessage = deviceMessage;
            try
            {
                pProof = IP.Deserialize<PresentationProof>(proofJson);
                pProof.Verify(vppp);
            }
            catch (InvalidUProveArtifactException e)
            {
                LogService.Log(LogService.LogType.FatalError, "IssuingVerifier - Proof verification failed", e);
                throw new Exception("VerifyProof - Proof verification failed", e);
            }
            proofAccepted = true;
            tokenAccepted = true;
            LogService.Log(LogService.LogType.Info, "IssuingVerifier - Proof passed tests");
        }
        #endregion VerifyProof
    }
}
