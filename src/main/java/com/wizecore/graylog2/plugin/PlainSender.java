package com.wizecore.graylog2.plugin;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.logging.Logger;

import com.wizecore.graylog2.plugin.ssl.CustomSSLSyslogConfig;

import org.graylog2.plugin.Message;
import org.graylog2.syslog4j.SyslogIF;

/**
 * Formats fields into message text
 *

        <34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8
         ^priority
         	^ version
         	  ^ date
         	  						   ^ host
         	  						   						 ^ APP-NAME
         	  						   						 	^ structured data?
         	  						   						 	  ^ MSGID

 */
public class PlainSender implements MessageSender {
	private Logger log = Logger.getLogger(PlainSender.class.getName());

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

	/**
	 * From syslog4j
	 *
	 * @param dt
	 * @return
	 */
	public static void appendSyslogTimestamp(Date dt, StringBuilder buffer) {
		SimpleDateFormat dateFormat = DATE_FORMAT.get();
		String datePrefix = dateFormat.format(dt);

		int pos = buffer.length() + 4;
		buffer.append(datePrefix);

		//  RFC 3164 requires leading space for days 1-9
		if (buffer.charAt(pos) == '0') {
			buffer.setCharAt(pos,' ');
		}
	}

	@Override
	public void send(SyslogIF syslog, int level, Message msg) {
		StringBuilder out = STRING_BUILDER_CACHE.get();
		out.setLength(0);
		appendHeader(msg, out);
		out.append(msg.getMessage());
		String str = out.toString();
        syslog.log(level, str);
	}

	public static void appendHeader(Message msg, StringBuilder out) {
		Date dt = null;
		Object ts = msg.getField("timestamp");
		if (ts != null && ts instanceof Number) {
			dt = new Date(((Number) ts).longValue());
		}
		
		if (dt == null) {
			dt = new Date();
		}
		
		// Write time
		appendSyslogTimestamp(dt, out);
		out.append(" ");
		
		// Write source (host)
		String source = msg.getSource();
		if (source != null) {
			out.append(source).append(" ");
		} else {
			out.append("- ");
		}
		
		// Write service
		Object facility = msg.getField("facility");
		if (facility != null) {
			out.append(facility.toString()).append(" ");
		} else {
			out.append("- ");
		}
		
		// MSGID
		Object username = msg.getField("username");
		if (username != null) {
			out.append(username.toString()).append(" ");
		} else {
			out.append("- ");
		}
		
		out.append(' ');
	}
}
