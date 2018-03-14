using System;

namespace uprove_uprovecommunicationissuing
{
    public class CommunicationException : Exception
    {
        public CommunicationException()
        {
        }

        public CommunicationException(string message)
            : base(message)
        {
        }

        public CommunicationException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
