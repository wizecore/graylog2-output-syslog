package com.wizecore.graylog2.plugin;


import com.google.common.collect.ImmutableMap;
import com.google.inject.assistedinject.Assisted;
import com.wizecore.graylog2.plugin.ssl.CustomSSLSyslogConfig;

import org.graylog2.plugin.Message;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.BooleanField;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.DropdownField;
import org.graylog2.plugin.configuration.fields.TextField;
import org.graylog2.plugin.outputs.MessageOutput;
import org.graylog2.plugin.streams.Stream;
import org.graylog2.syslog4j.Syslog;
import org.graylog2.syslog4j.SyslogConfigIF;
import org.graylog2.syslog4j.SyslogIF;
import org.graylog2.syslog4j.SyslogRuntimeException;
import org.graylog2.syslog4j.impl.AbstractSyslogConfigIF;
import org.graylog2.syslog4j.impl.message.processor.SyslogMessageProcessor;
import org.graylog2.syslog4j.impl.message.processor.structured.StructuredSyslogMessageProcessor;
import org.graylog2.syslog4j.impl.net.tcp.TCPNetSyslogConfig;
import org.graylog2.syslog4j.impl.net.udp.UDPNetSyslogConfig;
import jakarta.inject.Inject;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;


/**
 * Implementation of plugin to Graylog 2.0+ to send stream via Syslog
 *
 * @author Huksley <huksley@sdot.ru>
 *     extended for Graylog 2.0+ by TCollins
 */
public class SyslogOutput implements MessageOutput {

	public final static int PORT_MIN = 9000;
	public final static int PORT_MAX = 9099;
	public final static byte[] BOM = { (byte) 0xEF, (byte) 0xBB, (byte) 0xBF };

	private Logger log = Logger.getLogger(SyslogOutput.class.getName());
	private String host;
	private int port;
	private String protocol;
	private SyslogIF syslog;
	private String format;
	private MessageSender sender;

	public static MessageSender createSender(String fmt, Configuration conf) {
		try {
			if (fmt == null || fmt.equalsIgnoreCase("plain")) {
				return new PlainSender();
			} else
			if (fmt == null || fmt.equalsIgnoreCase("transparent")) {
				return new TransparentSyslogSender(conf);
			} else
			if (fmt == null || fmt.equalsIgnoreCase("snare")) {
				return new SnareWindowsSender();
			} else
			if (fmt == null || fmt.equalsIgnoreCase("structured")) {
				return new StructuredSender();
			} else
			if (fmt == null || fmt.equalsIgnoreCase("full")) {
				return new FullSender();
			} else
			if (fmt == null || fmt.equalsIgnoreCase("cef")) {
				return new CEFSender();
			} else
			if (fmt == null || fmt.toLowerCase().startsWith("custom:")) {
				String clazz = fmt.substring(fmt.indexOf(":") + 1);
				return (MessageSender) Class.forName(clazz).newInstance();
			} else {
				throw new IllegalArgumentException("Unknown format: " + fmt);
			}
		} catch (Exception e) {
			throw new IllegalArgumentException("Unable to accept format: " + fmt, e);
		}
	}


	@Inject
	public SyslogOutput(@Assisted Stream stream, @Assisted Configuration conf) {
		host = conf.getString("host");
		port = Integer.parseInt(conf.getString("port"));
		protocol = conf.getString("protocol");
		format = conf.getString("format");
		if (format == null || format.equals("")) {
			format = "plain";
		}

		log.info("Creating syslog output " + protocol + "://" + host + ":" + port + ", format " + format);
		SyslogConfigIF config = null;
		if (protocol.toLowerCase().equals("udp")) {
			config = new UDPNetSyslogConfig();
		} else
		if (protocol.toLowerCase().equals("tcp")) {
			config = new TCPNetSyslogConfig();
		} else
		if (protocol.toLowerCase().equals("tcp-ssl")) {
            CustomSSLSyslogConfig sslConfig = new CustomSSLSyslogConfig();
			String ks = conf.getString("keystore");
			String ksp = conf.getString("keystorePassword");
			String ts = conf.getString("truststore");
			String tsp = conf.getString("truststorePassword");

			if (ts == null || ts.trim().equals("")) {
				ts = ks;
			}
			
			if (tsp == null || tsp.trim().equals("")) {
				tsp = ksp;
			}
			
			if (ksp == null) {
				ksp = "";
			}
			
			if (ks == null) {
				throw new IllegalArgumentException("Keystore not defined!");
			}
			
			config = sslConfig;
			sslConfig.setKeyStore(ks);
			sslConfig.setKeyStorePassword(ksp);
			sslConfig.setTrustStore(ts);
			sslConfig.setTrustStorePassword(tsp);
		} else {
			throw new IllegalArgumentException("Unknown protocol: " + protocol);
		}

		config.setHost(host);
		config.setPort(port);
		int maxlen = 16 * 1024;
		try {
			maxlen = Integer.parseInt(conf.getString("maxlen"));
		} catch (Exception e) {
			// Don`t care
		}
		config.setMaxMessageLength(maxlen);
		config.setTruncateMessage(true);

		// Set maximum queue size to prevent OOM under high load (issue #61)
		// Default is unlimited which causes memory leaks
		int maxQueueSize = 500; // Conservative default
		try {
			String queueSizeStr = conf.getString("maxQueueSize");
			if (queueSizeStr != null && !queueSizeStr.trim().isEmpty()) {
				maxQueueSize = Integer.parseInt(queueSizeStr);
			}
		} catch (Exception e) {
			log.warning("Failed to parse maxQueueSize, using default: " + maxQueueSize);
		}
		// setMaxQueueSize is available on AbstractSyslogConfigIF, which all configs implement
		if (config instanceof AbstractSyslogConfigIF) {
			((AbstractSyslogConfigIF) config).setMaxQueueSize(maxQueueSize);
			log.info("Set maxQueueSize to " + maxQueueSize + " for " + protocol + "://" + host + ":" + port);
		}

		String hash = protocol + "_" + host + "_" + port + "_" + format;
		syslog = Syslog.exists(hash) ? Syslog.getInstance(hash) : Syslog.createInstance(hash, config);

		boolean utf8 = conf.getBoolean("utf8");
		if (utf8) {
			syslog.setMessageProcessor(new SyslogMessageProcessor() {
				public byte[] createPacketData(byte[] header, byte[] message, int start, int length, byte[] splitBeginText, byte[] splitEndText) {
					byte[] buf = super.createPacketData(header, message, start, length, splitBeginText, splitEndText);
					byte[] newBuf = new byte[buf.length + BOM.length];
					System.arraycopy(BOM, 0, newBuf, 0, BOM.length);
					System.arraycopy(buf, 0, newBuf, BOM.length, buf.length);
					return newBuf;
				}
			});

			syslog.setStructuredMessageProcessor(new StructuredSyslogMessageProcessor() {
				public byte[] createPacketData(byte[] header, byte[] message, int start, int length, byte[] splitBeginText, byte[] splitEndText) {
					byte[] buf = super.createPacketData(header, message, start, length, splitBeginText, splitEndText);
					byte[] newBuf = new byte[buf.length + BOM.length];
					System.arraycopy(BOM, 0, newBuf, 0, BOM.length);
					System.arraycopy(buf, 0, newBuf, BOM.length, buf.length);
					return newBuf;
				}
			});
		}

		sender = createSender(format, conf);

		if (sender instanceof TransparentSyslogSender) {
			// Always send empty header, which we will construct ourselves
			syslog.setMessageProcessor(new SyslogMessageProcessor() {
				@Override
				public String createSyslogHeader(int facility, int level, String localName, boolean sendLocalName, Date datetime) {
					return "";
				}

				@Override
				public String createSyslogHeader(int facility, int level, String localName, boolean sendLocalTimestamp, boolean sendLocalName) {
					return "";
				}
			});
		} else
		if (sender instanceof StructuredSender) {
			// Always send via structured data
			syslog.getConfig().setUseStructuredData(true);
		} else if (sender instanceof PlainSender || sender instanceof CEFSender) {
			// Will write this fields manually
			syslog.getConfig().setSendLocalName(false);
			syslog.getConfig().setSendLocalTimestamp(false);
		}
	}

	@Override
	public boolean isRunning() {
		return syslog != null;
	}

	@Override
	public void stop() {
        SyslogIF syslog = this.syslog;
		if (syslog != null) {
			log.info("Stopping syslog instance: " + syslog);
            syslog.shutdown();
			if (Syslog.exists(syslog.getProtocol())) {
                try {
    				Syslog.destroyInstance(syslog);
                } catch (SyslogRuntimeException e ) {
                    // Don't care
			    }
            }
			this.syslog = null;
		}
	}

	@Override
	public void write(List<Message> msgs) throws Exception {
		for (Message msg: msgs) {
			write(msg);
		}
	}

	@Override
	public void write(Message msg) throws Exception {
		int level = -1;

		if (level < 0) {
			Object mlev = msg.getField("level");
			if (mlev != null && mlev instanceof Number) {
				level = ((Number) mlev).intValue();
			}
		}

		if (level < 0) {
			Object mlev = msg.getField("_level");
			if (mlev != null && mlev instanceof Number) {
				level = ((Number) mlev).intValue();
			}
		}

		if (level < 0) {
			Object mlev = msg.getField("original_level");
			if (mlev != null && mlev instanceof String) {
				if (mlev.toString().equalsIgnoreCase("INFO")) {
					level = SyslogIF.LEVEL_INFO;
				} else
				if (mlev.toString().equalsIgnoreCase("SEVERE")) {
					level = SyslogIF.LEVEL_ERROR;
				} else
				if (mlev.toString().equalsIgnoreCase("WARNING")) {
					level = SyslogIF.LEVEL_WARN;
				};
			}
		}

		if (level < 0) {
			level = SyslogIF.LEVEL_INFO;
		}

		if (sender != null) {
			sender.send(syslog, level, msg);
		} else {
			syslog.log(level, msg.getMessage());
		}
	}

	public interface Factory extends MessageOutput.Factory<SyslogOutput> {
		@Override
		SyslogOutput create(Stream stream, Configuration configuration);

		@Override
		Config getConfig();

		@Override
		Descriptor getDescriptor();
	}

	public static class Descriptor extends MessageOutput.Descriptor {
		public Descriptor() {
			super("Syslog Output", false, "", "Forwards stream to Syslog.");
		}
	}

	public static class Config extends MessageOutput.Config {
		@Override
		public ConfigurationRequest getRequestedConfiguration() {
			final ConfigurationRequest configurationRequest = new ConfigurationRequest();

			final Map<String, String> protocols = ImmutableMap.of("tcp", "TCP", "udp", "UDP", "tcp-ssl", "SSL/TLS over TCP");
			configurationRequest.addField(new DropdownField(
					"protocol", "Message dispatch protocol", "tcp", protocols,
					"The protocol that should be used to send messages to the remote syslog server",
					ConfigurationField.Optional.NOT_OPTIONAL)
			);

			configurationRequest.addField(new TextField("host", "Syslog host", "localhost", "Remote host to send syslog messages to.", ConfigurationField.Optional.NOT_OPTIONAL));
			configurationRequest.addField(new TextField("port", "Syslog port", "514", "Syslog port on the remote host. Default is 514.", ConfigurationField.Optional.NOT_OPTIONAL));

			HashMap<String, String> types = new HashMap<String, String>();
			types.put("plain", "plain");
			types.put("structured", "structured");
			types.put("cef", "cef");
			types.put("full", "full");
			types.put("transparent", "transparent");
			types.put("snare", "snare");

			// Make immutable map from types
			final Map<String, String> formats = ImmutableMap.copyOf(types);

			configurationRequest.addField(new DropdownField(
					"format", "Message format", "plain", formats,
					"Message format. For detailed explanation, see https://github.com/wizecore/graylog2-output-syslog",
					ConfigurationField.Optional.NOT_OPTIONAL)
			);
			configurationRequest.addField(new BooleanField("transparentFormatRemoveHeader", "Remove header (only for transparent)", false, "Do not insert header when it forwards the message content."));

			configurationRequest.addField(new TextField("maxlen", "Maximum message length", "", "Maximum message (body) length. Longer messages will be truncated. If not specified defaults to 16384 bytes.", ConfigurationField.Optional.OPTIONAL));

			configurationRequest.addField(new TextField("maxQueueSize", "Maximum queue size", "500", "Maximum number of messages to queue internally. Set to -1 for unlimited. Default is 500.", ConfigurationField.Optional.OPTIONAL));

			configurationRequest.addField(new TextField("keystore", "Key store", "", "Path to Java keystore (required for SSL over TCP). Must contain private key and cert for this client.", ConfigurationField.Optional.OPTIONAL));
			configurationRequest.addField(new TextField("keystorePassword", "Key store password", "", "", ConfigurationField.Optional.OPTIONAL));

			configurationRequest.addField(new TextField("truststore", "Trust store", "", "Path to Java keystore (required for SSL over TCP). Optional (if not set, equals to key store). Must contain peers we trust connecting to.", ConfigurationField.Optional.OPTIONAL));
			configurationRequest.addField(new TextField("truststorePassword", "Trust store password", "", "", ConfigurationField.Optional.OPTIONAL));

			configurationRequest.addField(new BooleanField("utf8", "UTF-8 BOM", false,"Always add BOM to messages send. Use this to conform to RFC 5424 requirements for UTF-8 messages."));
			return configurationRequest;
		}
	}

}
