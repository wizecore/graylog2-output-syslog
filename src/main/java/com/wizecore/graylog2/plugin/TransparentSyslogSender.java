package com.wizecore.graylog2.plugin;

import org.graylog2.plugin.Message;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.syslog4j.SyslogConstants;
import org.graylog2.syslog4j.SyslogIF;
import org.joda.time.DateTime;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.logging.Logger;

import com.wizecore.graylog2.plugin.ssl.CustomSSLSyslogConfig;

/**
 * Retain as much as possible original message, facility and level, giving maximum compatibility to the Graylog internal syslog input,
 * so that messages recevied will be sent unmodified to the remote syslog server.
 */
public class TransparentSyslogSender implements MessageSender {
	private Logger log = Logger.getLogger(TransparentSyslogSender.class.getName());
	private boolean removeHeader = false;

	public static final String SYSLOG_DATEFORMAT = "MMM dd HH:mm:ss";

	/**
	 * ThreadLocal SimpleDateFormat to avoid creating new instances on every message
	 * and avoid synchronization issues (SimpleDateFormat is not thread-safe)
	 */
	private static final ThreadLocal<SimpleDateFormat> DATE_FORMAT = new ThreadLocal<SimpleDateFormat>() {
		@Override
		protected SimpleDateFormat initialValue() {
			return new SimpleDateFormat(SYSLOG_DATEFORMAT, Locale.ENGLISH);
		}
	};

	/**
	 * ThreadLocal StringBuilder to avoid allocating new StringBuilder on every message
	 */
	private static final ThreadLocal<StringBuilder> STRING_BUILDER_CACHE = new ThreadLocal<StringBuilder>() {
		@Override
		protected StringBuilder initialValue() {
			return new StringBuilder(256);
		}
	};

	public TransparentSyslogSender(Configuration conf) {
		removeHeader = conf.getBoolean("transparentFormatRemoveHeader");
	}


	/**
	 * From syslog4j
	 *
	 * @param dt
	 * @return
	 */
	public static void appendSyslogTimestamp(Message msg, StringBuilder buffer) {
		SimpleDateFormat dateFormat = DATE_FORMAT.get();

		Date dt = null;
		Object ts = msg.getField("timestamp");
		if (ts instanceof Number) {
			dt = new Date(((Number) ts).longValue());
		} else if (ts instanceof DateTime) {
			DateTime jt = ((DateTime) ts);
			dt = jt.toDate();
		} else {
			System.out.println("Missing timestamp: " + msg.getId() + ", " + ts);
		}

		if (dt == null) {
			dt = new Date();
		}

		String datePrefix = dateFormat.format(dt);

		int pos = buffer.length() + 4;
		buffer.append(datePrefix);

		//  RFC 3164 requires leading space for days 1-9
		if (buffer.charAt(pos) == '0') {
			buffer.setCharAt(pos, ' ');
		}
	}

	protected int findFacility(Message msg) {
		int facility = SyslogConstants.FACILITY_USER;
		// Use field from
		Object fn = msg.getField("facility_num");
		if (fn instanceof Number) {
			return ((Number) fn).intValue();
		}

		fn = msg.getField("facility");
		if (fn instanceof Number) {
			facility = ((Number) fn).intValue();
		} else if (fn instanceof String) {
			String fs = ((String) fn);
			// NB: Keep in sync with org.graylog2.plugin.Tools#syslogFacilityToReadable
			switch (fs) {
				case "kernel":
					facility = 0;
					break;
				case "user-level":
					facility = 1;
					break;
				case "mail":
					facility = 2;
					break;
				case "system daemon":
					facility = 3;
					break;
				case "security/authorization":
					// SyslogConstants.FACILITY_AUTH
					facility = 4;
					// SyslogConstants.FACILITY_AUTHPRIV
					// facility = 10;
					break;
				case "syslogd":
					facility = 5;
					break;
				case "line printer":
					facility = 6;
					break;
				case "network news":
					facility = 7;
					break;
				case "UUCP":
					facility = 8;
					break;
				case "clock":
					// SyslogConstants.FACILITY_CLOCK
					facility = 9;
					// SyslogConstants.FACILITY_CLOCK2
					// facility = 15;
					break;
				case "FTP":
					facility = 11;
					break;
				case "NTP":
					facility = 12;
					break;
				case "log audit":
					facility = 13;
					break;
				case "log alert":
					facility = 14;
					break;
				case "local0":
					facility = 16;
					break;
				case "local1":
					facility = 17;
					break;
				case "local2":
					facility = 18;
					break;
				case "local3":
					facility = 19;
					break;
				case "local4":
					facility = 20;
					break;
				case "local5":
					facility = 21;
					break;
				case "local6":
					facility = 22;
					break;
				case "local7":
					facility = 23;
					break;
				case "Unknown":
				default:
					System.err.println("Unknown literal facility: " + msg.getId() + ", " + fn);
					facility = SyslogConstants.FACILITY_USER;
			}
		}
		return facility;
	}

	protected void appendPriority(Message msg, int level, StringBuilder out) {
		int facility = findFacility(msg);
		facility = facility << 3;
		int priority = facility + level;
		out.append("<");
		out.append(priority);
		out.append(">");
	}

	@Override
	public void send(SyslogIF syslog, int level, Message msg) {
		StringBuilder out = STRING_BUILDER_CACHE.get();
		out.setLength(0);
		if (!removeHeader) {
			appendHeader(msg, level, out);
		}

		// Remove source (hostname) from source message
		String str = msg.getMessage();
		String source = msg.getSource();
		if (source != null && str.startsWith(source) && str.substring(source.length(), source.length() + 1).equals(" ")) {
			str = str.substring(source.length() + 1);
		}
		out.append(str);
        syslog.log(level, out.toString());
	}

	protected void appendLocalName(Message msg, StringBuilder out) {
		// Write source (host)
		String source = msg.getSource();
		if (source != null) {
			out.append(source);
		} else {
			out.append("-");
		}
	}

	public void appendHeader(Message msg, int level, StringBuilder out) {
		appendPriority(msg, level, out);
		appendSyslogTimestamp(msg, out);
		out.append(" ");
		appendLocalName(msg, out);
		out.append(" ");
	}
}
