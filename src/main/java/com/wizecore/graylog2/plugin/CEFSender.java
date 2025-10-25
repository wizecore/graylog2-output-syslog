package com.wizecore.graylog2.plugin;

import java.util.Map;

import org.graylog2.plugin.Message;
import org.graylog2.syslog4j.SyslogConstants;
import org.graylog2.syslog4j.SyslogIF;

/**
 * Using CEF format
 */

/*
 * http://blog.rootshell.be/2011/05/11/ossec-speaks-arcsight/
 *
 *
 * CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

CEF:0|ArcSight|Logger|5.0.0.5355.2|sensor:115|Logger Internal Event|1|\
cat=/Monitor/Sensor/Fan5 cs2=Current Value cnt=1 dvc=10.0.0.1 cs3=Ok \
cs1=null type=0 cs1Label=unit rt=1305034099211 cs3Label=Status cn1Label=value \
cs2Label=timeframe
 */
public class CEFSender implements MessageSender {

	/**
	 * ThreadLocal StringBuilder to avoid allocating new StringBuilder on every message
	 */
	private static final ThreadLocal<StringBuilder> STRING_BUILDER_CACHE = new ThreadLocal<StringBuilder>() {
		@Override
		protected StringBuilder initialValue() {
			return new StringBuilder(512);
		}
	};

	@Override
	public void send(SyslogIF syslog, int level, Message msg) {
		StringBuilder out = STRING_BUILDER_CACHE.get();
		out.setLength(0);
		
		// Header:
		// CEF:Version|Device Vendor|Device Product|Device Version|
		out.append("CEF:0|Graylog|graylog-output-syslog:cefsender|2.3.1|");
		
		// Device Event Class ID
		out.append("log:1");
		out.append("|");

		Map<String, Object> fields = msg.getFields();
		Object fv = fields.get("act");
		
		// Name
		String str = fv != null ? fv.toString() : null;
		if (str == null) {
			fv = fields.get("short_message");
			str = fv != null ? fv.toString() : null;
		}
		if (str == null) {
			str = msg.getId();
		}
		str = escape(str, false);
		out.append(str);
		
		// Severity
		// The valid integer values are 0-3=Low, 4-6=Medium, 7-8=High, and 9-10=Very-High.
		int cefLevel = 0;
		/** see {@link org.graylog2.syslog4j.SyslogConstants#LEVEL_INFO} */
		switch (level) {
			case (SyslogConstants.LEVEL_DEBUG):
				cefLevel = 1;
				break;
			case (SyslogConstants.LEVEL_NOTICE):
				cefLevel = 2;
				break;
			case (SyslogConstants.LEVEL_INFO):
				cefLevel = 3;
				break;
			case (SyslogConstants.LEVEL_WARN):
				cefLevel = 6;
				break;
			case (SyslogConstants.LEVEL_ERROR):
				cefLevel = 7;
				break;
			case (SyslogConstants.LEVEL_CRITICAL):
				cefLevel = 8;
				break;
			case (SyslogConstants.LEVEL_ALERT):
				cefLevel = 9;
				break;
			case (SyslogConstants.LEVEL_EMERGENCY):
				cefLevel = 10;
				break;
			default:
				// FIXME: Unknown level
				cefLevel = 10;
				break;
		}
		out.append("|").append(cefLevel) .append("|"); 
		
		// Extension
		boolean have = false;
		boolean haveExternalId = false;
		boolean haveMsg = false;
		boolean haveStart = false;
		for (String k: fields.keySet()) {
			Object v = fields.get(k);
			if (!k.equals("message") && !k.equals("full_message") && !k.equals("short_message")) {
    			String s = v != null ? v.toString() : "null";
				s = escape(s, true);
				if (have) {
					out.append(" ");
				}
				out.append(k).append('=').append(s);
				have = true;
				
				if (!haveExternalId && k.equals("externalId")) {
					haveExternalId = true;
				}
				
				if (!haveMsg && k.equals("msg")) {
					haveMsg = true;
				}
				
				if (!haveStart && k.equals("start")) {
					haveStart = true;
				}
			}
		}
		
		if (!haveStart) {
			out.append(" start=").append(msg.getTimestamp().getMillis());
		}
		
		if (!haveMsg) {
			out.append(" msg=").append(escape(msg.getMessage(), true));
		}
		
		if (!haveExternalId) {
			out.append(" externalId=").append(msg.getId());
		}
		
		syslog.log(level, out.toString());
	}

	public String escape(String s, boolean extension) {
		s = s.replace("\\", "\\\\");
		if (extension) {
			s = s.replace("=", "\\=");
			s = s.replace("\r", "");
			s = s.replace("\n", "\\n");
		} else {
			s = s.replace("|", "\\|");
			s = s.replace("\r", "");
			s = s.replace("\n", "");
		}
		return s;
	}
}
