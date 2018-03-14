using System.IO;
using System.Reflection;
using System.Text;

namespace uprove_uprovecommunicationissuing_tests
{
    public class TestHelper
    {

        public string ReadFile(string filename)
        {
            string path = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), @"Files\" + filename + ".txt");
            string[] files = File.ReadAllLines(path);
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < files.Length; i++)
                sb.Append(files[i].ToString().Trim());

            return sb.ToString();
        }
    }
}
