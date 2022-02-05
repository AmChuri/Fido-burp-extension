package src.main.eu.devity.burp.fidoiot.utilities;

import burp.*;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Objects;

/**
 * Logger for FIDO Burp Extension
 */
public class Logger {

    private static PrintWriter stdout = null;
    private static PrintWriter stderr = null;

    public enum LogLevel {
        ERROR,
        INFO,
        DEBUG
    }

    private Logger() {
        stdout = BurpExtender.getStdOut();
        stderr = BurpExtender.getStdErr();
    }

    private static class SingletonHolder {
        private static final Logger INSTANCE = new Logger();
    }

    public static Logger getInstance() {
        return SingletonHolder.INSTANCE;
    }

    public void log(Class callingClass, String message, LogLevel logType) {
        // Get current time
        Calendar calObj = Calendar.getInstance();
        SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
        String time = dateFormat.format(calObj.getTime());

        // Choose correct output stream
        PrintWriter outputStream;
        outputStream = (Objects.equals(logType, LogLevel.ERROR)) ? stderr : stdout;


//        if (outputStream != null && logType.ordinal() <= logType) {
            String logTypeName = logType.name();

            // Print log message
            String logOutput = String.format("[%s] %s - [%s]: %s ", logTypeName, time, callingClass.getSimpleName(), message);
            outputStream.println(logOutput);
//        }
    }

    public String logToString(Class callingClass, String message, LogLevel logType) {
        // Get current time
        Calendar calObj = Calendar.getInstance();
        SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
        String time = dateFormat.format(calObj.getTime());

        // Choose correct output stream
        PrintWriter outputStream;
        outputStream = (Objects.equals(logType, LogLevel.ERROR)) ? stderr : stdout;


//        if (outputStream != null && logType.ordinal() <= logType) {
            String logTypeName = logType.name();

            // Print log message
            String logOutput = String.format("[%s] %s - [%s]: %s ", logTypeName, time, callingClass.getSimpleName(), message);
           
            return logOutput;
//        }
    }

}