package com.heli.endpoints;

import com.heli.attribute.RadiusAttribute;
import com.heli.exception.RadiusException;
import com.heli.packet.AccessRequest;
import com.heli.packet.AccountingRequest;
import com.heli.packet.RadiusPacket;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.*;
import java.util.*;
import java.util.concurrent.ExecutorService;

/**
 * Implements a simple Radius server. This class must be subclassed to
 * provide an implementation for getSharedSecret() and getUserPassword().
 * If the server supports accounting, it must override
 * accountingRequestReceived().
 */
@Component
@Slf4j
public abstract class AbstractRadiusServer {

	private InetAddress listenAddress;
	private int authPort;
	private int acctPort;
	private DatagramSocket authSocket;
	private DatagramSocket acctSocket;
	private int socketTimeout;
	private final HashMap<String, Long> receivedPackets = new HashMap<>();
	private long lastClean;
	private long duplicateInterval; // 30 s
	protected transient boolean closing = false;
	private Boolean enableAuth;
	private Boolean enableAccount;

	@Autowired
	private ObjectFactory<RadiusPacket> radiusPacketObjectFactory;


	public ExecutorService getExecutor() {
		return executor;
	}

	public void setExecutor(ExecutorService executor) {
		this.executor = executor;
	}

	public Boolean getEnableAuth() {
		return enableAuth;
	}

	public void setEnableAuth(Boolean enableAuth) {
		this.enableAuth = enableAuth;
	}

	public Boolean getEnableAccount() {
		return enableAccount;
	}

	public void setEnableAccount(Boolean enableAccount) {
		this.enableAccount = enableAccount;
	}

	/**
	 * Define this executor in child class to make packet processing be made in separate threads
	 */
	private ExecutorService executor = null;
	
	/**
	 * Returns the shared secret used to communicate with the client with the
	 * passed IP address or null if the client is not allowed at this server.
	 * 
	 * @param client
	 *            IP address and port number of client
	 * @return shared secret or null
	 */
	public abstract String getSharedSecret(InetSocketAddress client);

	/**
	 * Returns the shared secret used to communicate with the client with the
	 * passed IP address and the received packet data or null if the client 
	 * is not allowed at this server.
	 *
	 * for compatiblity this standard implementation just call the getSharedSecret(InetSocketAddress) method
	 * and should be overrived when necessary
	 * 
	 * @param client
	 *            IP address and port number of client
	 * @param packet
	 *            packet received from client, the packettype comes as RESERVED, 
	 *	      because for some packets the secret is necessary for decoding
	 * @return shared secret or null
	 */
	public String getSharedSecret(InetSocketAddress client, RadiusPacket packet) {
		return getSharedSecret(client);
	}

	/**
	 * Returns the password of the passed user. Either this
	 * method or accessRequestReceived() should be overriden.
	 * 
	 * @param userName
	 *            user name
	 * @return plain-text password or null if user unknown
	 */
	public abstract String getUserPassword(String userName);

	/**
	 * Constructs an answer for an Access-Request packet. Either this
	 * method or isUserAuthenticated should be overriden.
	 * 
	 * @param accessRequest
	 *            Radius request packet
	 * @param client
	 *            address of Radius client
	 * @return response packet or null if no packet shall be sent
	 * @exception RadiusException
	 *                malformed request packet; if this
	 *                exception is thrown, no answer will be sent
	 */
	public RadiusPacket accessRequestReceived(AccessRequest accessRequest, InetSocketAddress client) throws RadiusException {
		String plaintext = getUserPassword(accessRequest.getUserName());
		int type = RadiusPacket.ACCESS_REJECT;
		if (plaintext != null && accessRequest.verifyPassword(plaintext))
			type = RadiusPacket.ACCESS_ACCEPT;
		RadiusPacket radiusPacket = radiusPacketObjectFactory.getObject();
		radiusPacket.setPacketType(type);
		radiusPacket.setPacketIdentifier(accessRequest.getPacketIdentifier());
		copyProxyState(accessRequest, radiusPacket);
		return radiusPacket;
	}

	/**
	 * Constructs an answer for an Accounting-Request packet. This method
	 * should be overriden if accounting is supported.
	 * 
	 * @param accountingRequest
	 *            Radius request packet
	 * @param client
	 *            address of Radius client
	 * @return response packet or null if no packet shall be sent
	 * @exception RadiusException
	 *                malformed request packet; if this
	 *                exception is thrown, no answer will be sent
	 */
	public RadiusPacket accountingRequestReceived(AccountingRequest accountingRequest, InetSocketAddress client) throws RadiusException {
		RadiusPacket radiusPacket = radiusPacketObjectFactory.getObject();
		radiusPacket.setPacketType(RadiusPacket.ACCOUNTING_RESPONSE);
		radiusPacket.setPacketIdentifier(accountingRequest.getPacketIdentifier());
		copyProxyState(accountingRequest, radiusPacket);
		return radiusPacket;
	}

	/**
	 * Starts the Radius server.
	 */
	public void start() {
		if (executor == null){
			log.info("using single thread mode");
		}else {
			log.info("using multi thread mode");
		}
		if (enableAuth) {
			new Thread() {
				public void run() {
					setName("Radius Auth Listener");
					try {
						log.info("starting RadiusAuthListener on port " + getAuthPort());
						listenAuth();
						log.info("RadiusAuthListener is being terminated");
					}
					catch (Exception e) {
						e.printStackTrace();
						log.error("auth thread stopped by exception", e);
					}
					finally {
						authSocket.close();
						log.debug("auth socket closed");
					}
				}
			}.start();
		}

		if (enableAccount) {
			new Thread() {
				public void run() {
					setName("Radius Acct Listener");
					try {
						log.info("starting RadiusAcctListener on port " + getAcctPort());
						listenAcct();
						log.info("RadiusAcctListener is being terminated");
					}
					catch (Exception e) {
						e.printStackTrace();
						log.error("acct thread stopped by exception", e);
					}
					finally {
						acctSocket.close();
						log.debug("acct socket closed");
					}
				}
			}.start();
		}
	}

	/**
	 * Stops the server and closes the sockets.
	 */
	public void stop() {
		log.info("stopping Radius server");
		closing = true;
		if (executor != null) 
			executor.shutdown();
		if (authSocket != null)
			authSocket.close();
		if (acctSocket != null)
			acctSocket.close();
	}

	/**
	 * Returns the auth port the server will listen on.
	 * 
	 * @return auth port
	 */
	public int getAuthPort() {
		return authPort;
	}

	/**
	 * Sets the auth port the server will listen on.
	 * 
	 * @param authPort
	 *            auth port, 1-65535
	 */
	public void setAuthPort(int authPort) {
		if (authPort < 1 || authPort > 65535)
			throw new IllegalArgumentException("bad port number");
		this.authPort = authPort;
		this.authSocket = null;
	}

	/**
	 * Returns the socket timeout (ms).
	 * 
	 * @return socket timeout
	 */
	public int getSocketTimeout() {
		return socketTimeout;
	}

	/**
	 * Sets the socket timeout.
	 * 
	 * @param socketTimeout
	 *            socket timeout, >0 ms
	 * @throws SocketException
	 */
	public void setSocketTimeout(int socketTimeout) throws SocketException {
		if (socketTimeout < 1)
			throw new IllegalArgumentException("socket tiemout must be positive");
		this.socketTimeout = socketTimeout;
		if (authSocket != null)
			authSocket.setSoTimeout(socketTimeout);
		if (acctSocket != null)
			acctSocket.setSoTimeout(socketTimeout);
	}

	/**
	 * Sets the acct port the server will listen on.
	 * 
	 * @param acctPort
	 *            acct port 1-65535
	 */
	public void setAcctPort(int acctPort) {
		if (acctPort < 1 || acctPort > 65535)
			throw new IllegalArgumentException("bad port number");
		this.acctPort = acctPort;
		this.acctSocket = null;
	}

	/**
	 * Returns the acct port the server will listen on.
	 * 
	 * @return acct port
	 */
	public int getAcctPort() {
		return acctPort;
	}

	/**
	 * Returns the duplicate interval in ms.
	 * A packet is discarded as a duplicate if in the duplicate interval
	 * there was another packet with the same identifier originating from the
	 * same address.
	 * 
	 * @return duplicate interval (ms)
	 */
	public long getDuplicateInterval() {
		return duplicateInterval;
	}

	/**
	 * Sets the duplicate interval in ms.
	 * A packet is discarded as a duplicate if in the duplicate interval
	 * there was another packet with the same identifier originating from the
	 * same address.
	 * 
	 * @param duplicateInterval
	 *            duplicate interval (ms), >0
	 */
	public void setDuplicateInterval(long duplicateInterval) {
		if (duplicateInterval <= 0)
			throw new IllegalArgumentException("duplicate interval must be positive");
		this.duplicateInterval = duplicateInterval;
	}

	/**
	* Returns a map containing received packets
	*
	* @return list of received packets
	*/
	public Map<String, Long> getReceivedPackets() {
		return receivedPackets;
	}

	/**
	 * Returns the IP address the server listens on.
	 * Returns null if listening on the wildcard address.
	 * 
	 * @return listen address or null
	 */
	public InetAddress getListenAddress() {
		return listenAddress;
	}

	/**
	 * Sets the address the server listens on.
	 * Must be called before start().
	 * Defaults to null, meaning listen on every
	 * local address (wildcard address).
	 * 
	 * @param listenAddress
	 *            listen address or null
	 */
	public void setListenAddress(InetAddress listenAddress) {
		this.listenAddress = listenAddress;
	}

	/**
	 * Copies all Proxy-State attributes from the request
	 * packet to the response packet.
	 * 
	 * @param request
	 *            request packet
	 * @param answer
	 *            response packet
	 */
	protected void copyProxyState(RadiusPacket request, RadiusPacket answer) {
		List<RadiusAttribute> proxyStateAttrs = request.getAttributes(33);
		for (RadiusAttribute stateAttr : proxyStateAttrs) {
			answer.addAttribute(stateAttr);
		}
	}

	/**
	 * Listens on the auth port (blocks the current thread).
	 * Returns when stop() is called.
	 * 
	 * @throws SocketException
	 * @throws InterruptedException
	 * 
	 */
	protected void listenAuth() throws SocketException {
		listen(getAuthSocket());
	}

	/**
	 * Listens on the acct port (blocks the current thread).
	 * Returns when stop() is called.
	 * 
	 * @throws SocketException
	 * @throws InterruptedException
	 */
	protected void listenAcct() throws SocketException {
		listen(getAcctSocket());
	}

	/**
	 * Listens on the passed socket, blocks until stop() is called.
	 * 
	 * @param s
	 *            socket to listen on
	 */
	protected void listen(final DatagramSocket s) {
		while (true) {
			try {
				final DatagramPacket packetIn = new DatagramPacket(new byte[RadiusPacket.MAX_PACKET_LENGTH], RadiusPacket.MAX_PACKET_LENGTH);
				// receive packet
				try {
					log.trace("about to call socket.receive()");
					s.receive(packetIn);
					if (log.isDebugEnabled())
						log.debug("receive buffer size = " + s.getReceiveBufferSize());
				}
				catch (SocketException se) {
					if (closing) {
						// end thread
						log.info("got closing signal - end listen thread");
						return;
					}
					// retry s.receive()
					log.error("SocketException during s.receive() -> retry", se);
					continue;
				}

				if (executor == null) {
					processRequest(s, packetIn);
				}
				else {
					executor.submit(new Runnable() {
						
						@Override
						public void run() {
							processRequest(s, packetIn);
						}
						
					});
				}
			}
			catch (SocketTimeoutException ste) {
				// this is expected behaviour
				log.trace("normal socket timeout");
			}
			catch (IOException ioe) {
				// error while reading/writing socket
				log.error("communication error", ioe);
			}
		}
	}


	/**
	 * Process a single received request
	 * 
	 * @param s
	 *            socket to send response on
	 * @param packetIn
	 *		data packet 
	 */
	protected void processRequest(final DatagramSocket s, final DatagramPacket packetIn) {
		try {
			// check client
			final InetSocketAddress localAddress = (InetSocketAddress) s.getLocalSocketAddress();
			final InetSocketAddress remoteAddress = new InetSocketAddress(packetIn.getAddress(), packetIn.getPort());
			final String secret = getSharedSecret(remoteAddress, makeRadiusPacket(packetIn, "1234567890", RadiusPacket.RESERVED));
			if (secret == null) {
				if (log.isInfoEnabled())
					log.info("ignoring packet from unknown client " + remoteAddress + " received on local address " + localAddress);
				return;
			}

			// parse packet
			final RadiusPacket request = makeRadiusPacket(packetIn, secret, RadiusPacket.UNDEFINED);
			if (log.isInfoEnabled())
				log.info("received packet from " + remoteAddress + " on local address " + localAddress + ": " + request);

			// handle packet
			log.trace("about to call RadiusServer.handlePacket()");
			final RadiusPacket response = handlePacket(localAddress, remoteAddress, request, secret);

			// send response
			if (response != null) {
				if (log.isInfoEnabled())
					log.info("send response: " + response);
				final DatagramPacket packetOut = makeDatagramPacket(response, secret, remoteAddress.getAddress(), packetIn.getPort(), request);
				s.send(packetOut);
			}
			else
				log.info("no response sent");
		}
		catch (IOException ioe) {
			// error while reading/writing socket
			log.error("communication error", ioe);
		}
		catch (RadiusException re) {
			// malformed packet
			log.error("malformed Radius packet", re);
		}
	}

	/**
	 * Handles the received Radius packet and constructs a response.
	 * 
	 * @param localAddress
	 *            local address the packet was received on
	 * @param remoteAddress
	 *            remote address the packet was sent by
	 * @param request
	 *            the packet
	 * @param sharedSecret
	 * @return response packet or null for no response
	 * @throws RadiusException
	 * @throws IOException
	 */
	protected RadiusPacket handlePacket(InetSocketAddress localAddress, InetSocketAddress remoteAddress, RadiusPacket request, String sharedSecret)
	        throws RadiusException, IOException {
		RadiusPacket response = null;

		// check for duplicates
		if (!isPacketDuplicate(request, remoteAddress)) {
			if (localAddress.getPort() == getAuthPort()) {
				// handle packets on auth port
				if (request instanceof AccessRequest)
					response = accessRequestReceived((AccessRequest) request, remoteAddress);
				else
					log.error("unknown Radius packet type: " + request.getPacketType());
			}
			else if (localAddress.getPort() == getAcctPort()) {
				// handle packets on acct port
				if (request instanceof AccountingRequest)
					response = accountingRequestReceived((AccountingRequest) request, remoteAddress);
				else
					log.error("unknown Radius packet type: " + request.getPacketType());
			}
			else {
				// ignore packet on unknown port
			}
		}
		else
			log.info("ignore duplicate packet");

		return response;
	}

	/**
	 * Returns a socket bound to the auth port.
	 * 
	 * @return socket
	 * @throws SocketException
	 */
	protected DatagramSocket getAuthSocket() throws SocketException {
		if (authSocket == null) {
			if (getListenAddress() == null)
				authSocket = new DatagramSocket(getAuthPort());
			else
				authSocket = new DatagramSocket(getAuthPort(), getListenAddress());
			authSocket.setSoTimeout(getSocketTimeout());
		}
		return authSocket;
	}

	/**
	 * Returns a socket bound to the acct port.
	 * 
	 * @return socket
	 * @throws SocketException
	 */
	protected DatagramSocket getAcctSocket() throws SocketException {
		if (acctSocket == null) {
			if (getListenAddress() == null)
				acctSocket = new DatagramSocket(getAcctPort());
			else
				acctSocket = new DatagramSocket(getAcctPort(), getListenAddress());
			acctSocket.setSoTimeout(getSocketTimeout());
		}
		return acctSocket;
	}

	/**
	 * Creates a Radius response datagram packet from a RadiusPacket to be send.
	 * 
	 * @param packet
	 *            RadiusPacket
	 * @param secret
	 *            shared secret to encode packet
	 * @param address
	 *            where to send the packet
	 * @param port
	 *            destination port
	 * @param request
	 *            request packet
	 * @return new datagram packet
	 * @throws IOException
	 */
	protected DatagramPacket makeDatagramPacket(RadiusPacket packet, String secret, InetAddress address, int port, RadiusPacket request)
	        throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		packet.encodeResponsePacket(bos, secret, request);
		byte[] data = bos.toByteArray();

		return new DatagramPacket(data, data.length, address, port);
	}

	/**
	 * Creates a RadiusPacket for a Radius request from a received
	 * datagram packet.
	 * 
	 * @param packet
	 *            received datagram
	 * @return RadiusPacket object
	 * @exception RadiusException
	 *                malformed packet
	 * @exception IOException
	 *                communication error (after getRetryCount()
	 *                retries)
	 */
	protected RadiusPacket makeRadiusPacket(DatagramPacket packet, String sharedSecret, int forceType) throws IOException, RadiusException {
		ByteArrayInputStream in = new ByteArrayInputStream(packet.getData());
		RadiusPacket radiusPacket = radiusPacketObjectFactory.getObject();
		return radiusPacket.decodeRequestPacket(in, sharedSecret, forceType);
	}

	/**
	 * Checks whether the passed packet is a duplicate.
	 * A packet is duplicate if another packet with the same identifier
	 * has been sent from the same host in the last time.
	 * 
	 * @param packet
	 *            packet in question
	 * @param address
	 *            client address
	 * @return true if it is duplicate
	 */
	protected boolean isPacketDuplicate(RadiusPacket packet, InetSocketAddress address) {
		long now = System.currentTimeMillis();
		long intervalStart = now - getDuplicateInterval();

		byte[] authenticator = packet.getAuthenticator();

		String uniqueKey = address.getAddress().getHostAddress()+ 
			packet.getPacketIdentifier() + 
			Arrays.toString(packet.getAuthenticator());

		synchronized (receivedPackets) {
			if (lastClean == 0 || lastClean < now - getDuplicateInterval()) {
				lastClean = now;
				for (Iterator<Map.Entry<String, Long>> i = receivedPackets.entrySet().iterator(); i.hasNext(); ) {
					Long receiveTime = i.next().getValue();
					if (receiveTime < intervalStart) {
						// packet is older than duplicate interval
						i.remove();
					}
				}
			}

			Long receiveTime = receivedPackets.get(uniqueKey);
			if (receiveTime == null) {
				receivedPackets.put(uniqueKey, System.currentTimeMillis());
				return false;
			} else {
				return !(receiveTime < intervalStart);
			}
		}
	}

}
