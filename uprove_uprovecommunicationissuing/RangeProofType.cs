using UProveCrypto.PolyProof;

namespace uprove_uprovecommunicationissuing
{
    /// <summary>
    /// Converts VerifierRangeProofParameters.ProofType into a string (<, <=, >=, >) and visa versa
    /// </summary>
    public class RangeProofType
    {
        private RangeProofType(string value, VerifierRangeProofParameters.ProofType proofType)
        {
            Value = value;
            ProofType = proofType;
        }

        public string Value { get; set; }
        public VerifierRangeProofParameters.ProofType ProofType { get; set; }

        public static RangeProofType LESS_THAN { get { return new RangeProofType("<", VerifierRangeProofParameters.ProofType.LESS_THAN); } }
        public static RangeProofType GREATER_THAN { get { return new RangeProofType(">", VerifierRangeProofParameters.ProofType.GREATER_THAN); } }
        public static RangeProofType LESS_THAN_OR_EQUAL_TO { get { return new RangeProofType("<=", VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO); } }
        public static RangeProofType GREATER_THAN_OR_EQUAL_TO { get { return new RangeProofType(">=", VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO); } }

        #region GetTypeToStringValue
        /// <summary>
        /// Converts a range proof value to a RangeProofType
        /// </summary>
        /// <param name="rangeProofValue">contains '<, <=, >=, >' </param>
        /// <returns>RangeProofType of the given string property or null if not exists</returns>
        public static RangeProofType GetType(string rangeProofValue)
        {
            if (rangeProofValue == LESS_THAN.Value)
                return LESS_THAN;
            else if (rangeProofValue == GREATER_THAN.Value)
                return GREATER_THAN;
            else if (rangeProofValue == LESS_THAN_OR_EQUAL_TO.Value)
                return LESS_THAN_OR_EQUAL_TO;
            else if (rangeProofValue == GREATER_THAN_OR_EQUAL_TO.Value)
                return GREATER_THAN_OR_EQUAL_TO;

            return null;
        }
        #endregion GetTypeToStringValue

        #region GetTypeToRangeProof
        /// <summary>
        /// Converts a range proof type to a string value
        /// </summary>
        /// <param name="proofType">range proof type to convert to string</param>
        /// <returns>converted range proof type as string or null if not exists</returns>
        public static RangeProofType GetType(VerifierRangeProofParameters.ProofType proofType)
        {
            if (proofType == LESS_THAN.ProofType)
                return LESS_THAN;
            else if (proofType == GREATER_THAN.ProofType)
                return GREATER_THAN;
            else if (proofType == LESS_THAN_OR_EQUAL_TO.ProofType)
                return LESS_THAN_OR_EQUAL_TO;
            else if (proofType == GREATER_THAN_OR_EQUAL_TO.ProofType)
                return GREATER_THAN_OR_EQUAL_TO;

            return null;
        }
        #endregion GetTypeToRangeProof
    }
}
