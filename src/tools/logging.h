#ifndef LOGGING_H
#define LOGGING_H

#include <iostream>
#include <string>
#include <fstream>
#include <ctime>
#include <chrono>
#include <iomanip>

struct timeData
{
	int year;
	int month;
	int day;
	int hour;
	int minute;
	int second;
};

// return the current timestamp as struct
inline timeData getCurrentTimestamp()
{
	// Obtiene el tiempo actual desde el epoch
	auto now = std::chrono::system_clock::now();
	// Convierte el tiempo a time_t para manipularlo como una estructura de tiempo tradicional
	std::time_t now_time = std::chrono::system_clock::to_time_t(now);

	// Convierte el tiempo a una estructura de tiempo
	struct tm *time = std::localtime(&now_time);

	return {
		time->tm_year + 1900,
		time->tm_mon + 1,
		time->tm_mday,
		time->tm_hour,
		time->tm_min,
		time->tm_sec};
}

enum LogLevel
{
	ERROR = 1,
	WARNING = 2,
	INFO = 3,
	DEBUG = 4
};

class logging
{
private:
#ifdef DEBUG
#define DEBUG_LOG 1
#else
#define DEBUG_LOG 0
#endif

	/// define posible options for the structure, such as:
	// [LEVEL] -> INDICATES THE IMPORTANCE OF THE LOG
	// %Y, %m, %d, %H, %M, %S -> OPTIONS FOR DATE AND TIME
	// [MESSAGE] -> THE MESSAGE TO BE LOGGED
	// [CONTENT]

	// DEFAULT LOG STRUCTURE
	std::string logStructure = "[[LEVEL]] - %Y-%m-%d %H:%M:%S - [MESSAGE] ([CONTENT])";
	std::string logFile = "log.txt";
	bool storeLog = false;

	int logLevel = 3;

	std::string getLogLevel(const int &logType)
	{
		switch (logType)
		{
		case 1:
			return "ERROR";
		case 2:
			return "WARNING";
		case 3:
			return "INFO";
		case 4:
			return "DEBUG";
		default:
			return "UNKNOWN";
		}
	}

	int replacer(std::string &stream, const std::string pattern, const std::string data, int len = 0)
	{
		if (len == 0)
			len = pattern.size();

		size_t pos = stream.find(pattern);
		if (pos != std::string::npos)
		{
			try
			{
				stream.replace(pos, len, data);
			}
			catch (const std::exception &e)
			{
				return -1;
			}
			return pos;
		}
		return -1;
	}

	void replaceData(std::string &stream, const std::string &logMessage, const std::string &logData, const timeData &time, const int &logType)
	{
		replacer(stream, "[CONTENT]", logData, 9);

		// replace date and time
		replacer(stream, "%Y", std::to_string(time.year), 2);
		replacer(stream, "%m", std::to_string(time.month), 2);
		replacer(stream, "%d", std::to_string(time.day), 2);
		replacer(stream, "%H", std::to_string(time.hour), 2);
		replacer(stream, "%M", std::to_string(time.minute), 2);
		replacer(stream, "%S", std::to_string(time.second), 2);

		// replace [MESSAGE]
		replacer(stream, "[MESSAGE]", logMessage, 9);

		// replace [LEVEL]
		replacer(stream, "[LEVEL]", getLogLevel(logType), 7);
	}

	void prototypeLog(const LogLevel &logType, const std::string &logMessage, const std::string &logData = "")
	{
		if(!DEBUG_LOG && logType == LogLevel::DEBUG) return;
		if (this->logLevel == 0)
			return;
        auto l = (int)logType;
        auto a = logType != LogLevel::DEBUG;
		if (this->logLevel < (int)logType && logType != LogLevel::DEBUG)
			return;

		std::string logResult = this->logStructure;
		std::string logLevel = getLogLevel(logType);

		timeData time = getCurrentTimestamp();

		replaceData(logResult, logMessage, logData, time, logType);

		if (this->storeLog)
		{
			try
			{
				std::ofstream logFile(this->logFile, std::ios::app);
				logFile << logResult << std::endl;
				logFile.close();
			}
			catch (const std::exception &e)
			{
				std::cerr << e.what() << '\n';
			}
		}
		std::cout << logResult << std::endl;
	}

public:
	enum class LoggingLevel
	{
		NO_LOGGING = 0,
		ONLY_ERRORS = 1,
		ERRORS_AND_WARNINGS = 2,
		ALL = 3
	};

	// levels of logging: 0 - no logging, 1 - errors only, 2 - errors and warnings, 3 - errors, warnings and info

	/// @brief Set the Log Config object
	/// @param level level of logging, 0 - no logging, 1 - errors only, 2 - errors and warnings, 3 - errors, warnings and info
	/// @param logStructure
	/// for example: "[LEVEL] - %Y-%m-%d %H:%M:%S" -> [INFO] - 2021-09-01 12:00:00
	/// @param logFile path to the file where the log will be stored
	void setLogConfig(int level, const std::string &logStructure, const std::string &logFile = "")
	{
		this->logLevel = level;
		this->logStructure = logStructure;
        this->storeLog = logFile.empty() ? false : true;

        if(this->storeLog){
            // check if the file exists and create it if it doesn't
            std::ofstream file(logFile, std::ios::app);
            file.close();
        }
        this->logFile = logFile;
	}

	/// @brief Print a log message
	/// @param message string with the message to log
	/// @param data additional data to log
	void log(const std::string &message, const std::string &data = "")
	{
		prototypeLog(INFO, message, data);
	}

	/// @brief Print a warning message
	/// @param message string with the message to log
	/// @param data additional data to log
	void warning(const std::string &message, const std::string &data = "")
	{
		prototypeLog(WARNING, message, data);
	}

    /// @brief Print an error message
    /// @param message string with the message to log
    /// @param data additional data to log
	void error(const std::string &message, const std::string &data = "")
	{
		prototypeLog(ERROR, message, data);
	}

    /// @brief Print a debug message
    /// @param message string with the message to log
    /// @param data additional data to log
	void debug(const std::string &message, const std::string &data = "")
	{
		prototypeLog(INFO, message, data);
	}

	class LogStream
	{
	public:
		LogStream(logging &logger, LogLevel level) : logger(logger), level(level) {}

		// Sobrecarga del operador << para manejar diferentes tipos de contenido
		template <typename T>
		LogStream &operator<<(const T &content)
		{
			stream << content;
			return *this;
		}

		// Destructor para manejar la salida del log
		~LogStream()
		{
			logger.prototypeLog(level, stream.str());
		}

	private:
		logging &logger;
		LogLevel level;
		std::ostringstream stream;
	};

	LogStream log()
	{
		return LogStream(*this, INFO);
	}

	LogStream warning()
	{
		return LogStream(*this, WARNING);
	}

	LogStream error()
	{
		return LogStream(*this, ERROR);
	}

	LogStream debug()
	{
		return LogStream(*this, DEBUG);
	}
};

#endif // LOGGING_H
