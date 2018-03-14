using System;
using System.Collections.Generic;
using System.Text;
using uprove_json;
using UProveCrypto.PolyProof;

namespace uprove_uprovecommunicationissuing
{
    #region RangeProofProperties
    public class RangeProofProperties
    {
        public string AttributeName { get; set; }
        public int Index { get; private set; }
        public int MinYear { get; private set; }
        public int MaxYear { get; private set; }

        public RangeProofProperties(string attributeName, int index, int minYear, int maxYear)
        {
            AttributeName = attributeName;
            Index = index;
            MinYear = minYear;
            MaxYear = maxYear;
        }
    }
    #endregion RangeProofProperties

    public class CommenIssuing
    {
        #region Properties
        private Encoding encoding = Encoding.UTF8;
        #endregion Properties

        #region ConvertAttributeListToBase64ByteArray
        /// <summary>
        /// Transfers the base64 encoded attribute values and properties 
        /// from the attributes property into a byte array
        /// </summary>
        /// <param name="attributes">List of attributes to get the attributes with their 
        /// properties in a byte array</param>
        /// <returns>attributes (values and properties) in an array</returns>
        public byte[][] ConvertAttributeListToBase64ByteArray(List<BasicClaim> attributes)
        {
            byte[][] byteList = new byte[attributes.Count * 2][];
            int counter = 0;
            
            for(int i = 0; i < attributes.Count; i++)
            {
                byteList[counter] = attributes[i].valuesbase64encoded;
                byteList[counter + 1] = attributes[i].propertiesbase64encoded;

                counter += 2;
            }

            return byteList;
        }
        #endregion ConvertAttributeListToBase64ByteArray

        #region CreateBase64ForAttributeList
        public void CreateBase64ForAttributeList(List<BasicClaim> attribteList, List<string> rangeProofDates, 
            out List<RangeProofProperties> rangeProofProperties)
        {
            byte[] propertiesBase64Encoded;
            rangeProofProperties = new List<RangeProofProperties>();
            
            for (int i = 0; i < attribteList.Count; i++)
            {
                propertiesBase64Encoded = new byte[] { };

                if (rangeProofDates.Contains(attribteList[i].name)) // e.g "swissEduPersonDateOfBirth"
                {
                    int miny, maxy, index;
                    propertiesBase64Encoded = PrepareDate(attribteList[i].values[0], out miny, out maxy);    // only able to include one date (limited by range proof)
                    index = (2 * i) + 1;
                    rangeProofProperties.Add(new RangeProofProperties(attribteList[i].name, index, miny, maxy));
                }
                else
                {
                    // get all attribute values out and add them together in a comma separated string
                    string allValues = string.Empty;
                    for(int j = 0; j < attribteList[i].values.Count; j++)
                    {
                        // if there is more than one value, separate them by comma
                        if (j > 0)
                            allValues += ", ";

                        allValues += attribteList[i].values[j];
                    }
                    propertiesBase64Encoded = encoding.GetBytes(allValues);
                }

                attribteList[i].valuesbase64encoded = propertiesBase64Encoded;
                attribteList[i].propertiesbase64encoded = encoding.GetBytes("{ \"name\": \"" + attribteList[i].name
                    + "\", \"qualitylevel\": \"" + attribteList[i].qualitylevel + "\" }");
            }
        }
        #endregion CreateBase64ForAttributeList

        #region PrepareDoB
        /// <summary>
        /// Calculates the dob attribute - converting is special
        /// </summary>
        /// <param name="dobValue">string value of the dob attribute</param>
        /// <returns>encrypted dob value</returns>
        private byte[] PrepareDate(string dobValue, out int minYear, out int maxYear)
        {
            DateTime minBirthdate = DateTime.Today.AddYears(-120);
            DateTime maxBirthdate = new DateTime(DateTime.Now.Year, 12, 31).AddYears(50);
            minYear = minBirthdate.Year;
            maxYear = maxBirthdate.Year;

            DateTime proverDoB = DateTime.ParseExact(dobValue, "dd.MM.yyyy", System.Globalization.CultureInfo.InvariantCulture);

            int encodedProverBirthday = RangeProofParameterFactory.EncodeYearAndDay(proverDoB, minBirthdate.Year);
            byte[] proverBirthdayAttribute = RangeProofParameterFactory.EncodeIntAsUProveAttribute(encodedProverBirthday);

            return proverBirthdayAttribute;
        }
        #endregion PrepareDoB
    }
}
