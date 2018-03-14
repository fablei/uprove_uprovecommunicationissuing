using System;

namespace uprove_uprovecommunicationissuing
{
    public class LogService
    {
        #region Properties
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        
        public enum LogType { Debug = 1, Info = 2, Warning = 3, Error = 4, Fatal = 5, FatalError = 6 };

        #endregion Properties

        #region Log
        /// <summary>
        /// Logs the given message to the given log type
        /// </summary>
        /// <param name="logType">type to put the log in</param>
        /// <param name="message">message to log</param>
        /// <param name="exception">exception to log (optional)</param>
        public static void Log(LogType logType, string message, Exception exception = null)
        {
            log.Debug(message, exception); // log debug mode everytime

            if (log.IsDebugEnabled && logType == LogType.Debug)
                return;
            if (log.IsInfoEnabled && logType == LogType.Info)
                log.Info(message, exception);
            if (log.IsWarnEnabled && logType == LogType.Warning)
                log.Warn(message, exception);
            if (log.IsErrorEnabled && (logType == LogType.Error
                || logType == LogType.FatalError))
                log.Error(message, exception);
            if (log.IsFatalEnabled && (logType == LogType.Fatal
                || logType == LogType.FatalError))
                log.Fatal(message, exception);
        }
        #endregion Log
    }
}
