package jenkins.security.plugins.ldap;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

public class BlindSSLSocketFactory extends SSLSocketFactory {
    private static final BlindSSLSocketFactory INSTANCE;

    static {
        final X509TrustManager dummyTrustManager =
                new X509TrustManager() {
                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                };
        try {
            final SSLContext context = SSLContext.getInstance("SSL");
            final TrustManager[] trustManagers = {dummyTrustManager};
            final SecureRandom rng = new SecureRandom();
            context.init(null, trustManagers, rng);
            INSTANCE = new BlindSSLSocketFactory(context.getSocketFactory());
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Cannot create BlindSslSocketFactory", e);
        }
    }

    public static SocketFactory getDefault() {
        return INSTANCE;
    }

    private final SSLSocketFactory sslFactory;

    private BlindSSLSocketFactory(SSLSocketFactory sslFactory) {
        this.sslFactory = sslFactory;
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose)
            throws IOException {
        return sslFactory.createSocket(s, host, port, autoClose);
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return sslFactory.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return sslFactory.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket() throws IOException {
        return sslFactory.createSocket();
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        return sslFactory.createSocket(host, port);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return sslFactory.createSocket(host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
            throws IOException, UnknownHostException {
        return sslFactory.createSocket(host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
            throws IOException {
        return sslFactory.createSocket(address, port, localAddress, localPort);
    }
}
