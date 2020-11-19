package org.webpagetest.vpntether;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.Toast;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Android VpnService which forwards traffic between the VPN tun interface and
 * an adb-forwarded UNIX socket. Adb forwarding can only connect to device-side
 * servers, so TetherService listens on a UNIX server socket.
 *
 * @author szym@google.com (Szymon Jakubczak)
 */
public class TetherService extends VpnService implements Handler.Callback {
    public static final String TAG = "VpnTetherService";
    public static final String DEFAULT_SOCKNAME = "vpntether";

    static {
        System.loadLibrary("native-lib");
    }

    private Handler mHandler;
    private Runner mRunner;
    private PendingIntent mConfigureIntent;

    class Runner implements Runnable {
        // Local (adb forwarded) socket to listen on.
        // We need to use UNIX sockets, because protecting adb-forwarded tcp does not work.
        private final String mServerSockName;

        // Write to this stream to kill the forwarder.
        private OutputStream mControl;

        private final Thread mThread;

        public Runner(String serverSockName) {
            mServerSockName = serverSockName;
            mThread = new Thread(this, "TetherService.Runner");
        }

        public void start() {
            mThread.start();
        }

        public void stop() {
            if (mControl != null) {
                try {
                    mControl.write(0);  // Interrupts |forward|.
                    mControl.close();
                } catch (IOException ignored) {}
                mControl = null;
            }
            // Just closing the server socket does not immediately interrupt accept.
            // See: https://code.google.com/p/android/issues/detail?id=29939
            // So instead send a special message to the socket.
            try {
                LocalSocket sock = new LocalSocket();
                sock.connect(new LocalSocketAddress(mServerSockName));
                DataOutputStream os = new DataOutputStream(sock.getOutputStream());
                os.writeChar(1);
                os.writeByte('q');
                os.flush();
            } catch (IOException ignored) {}
            try {
                mThread.join();
            } catch (InterruptedException ignored) {}
        }

        @Override
        public void run() {
            LocalServerSocket serverSocket = null;
            try {
                Log.i(TAG, "Listening on " + mServerSockName);
                serverSocket = new LocalServerSocket(mServerSockName);
                while (true) {
                    LocalSocket tunnel = serverSocket.accept();
                    Log.i(TAG, "Starting");

                    try {
                        // Read one length-prefixed string from channel to configure the interface.
                        DataInputStream dis = new DataInputStream(tunnel.getInputStream());
                        int length = dis.readChar();
                        if (length > 512) {
                            Log.i(TAG, "Bad configuration line");
                            tunnel.close();
                            continue;
                        }
                        byte[] configLine = new byte[length];
                        dis.readFully(configLine);
                        String parameters = new String(configLine, StandardCharsets.US_ASCII);
                        ParcelFileDescriptor vpnInterface = configure(parameters);
                        if (vpnInterface == null) {
                            Log.w(TAG, "Revoked!");
                            return;
                        }

                        Log.i(TAG, "Forwarding");
                        ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
                        mControl = new ParcelFileDescriptor.AutoCloseOutputStream(pipe[0]);
                        // |forward| closes all descriptors.
                        int result = forward(pipe[1].detachFd(),
                                ParcelFileDescriptor.dup(tunnel.getFileDescriptor()).detachFd(),
                                vpnInterface.detachFd());
                        Log.e(TAG, "forward exited with errno " + result);
                    } catch (Exception e) {
                        Log.e(TAG, "Failed", e);
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "Bailing", e);
            } finally {
                try {
                    if (serverSocket != null)
                        serverSocket.close();
                } catch (IOException ignored) {}
            }
        }

        private ParcelFileDescriptor configure(String parameters) throws Exception {
            // Configure a builder while parsing the parameters.
            Builder builder = new Builder();
            for (String parameter : parameters.split(" ")) {
                String[] fields = parameter.split(",");
                try {
                    switch (fields[0].charAt(0)) {
                        case 'q':
                            // Quit!
                            return null;
                        case 'm':
                            builder.setMtu(Short.parseShort(fields[1]));
                            break;
                        case 'a':
                            builder.addAddress(fields[1], Integer.parseInt(fields[2]));
                            break;
                        case 'r':
                            builder.addRoute(fields[1], Integer.parseInt(fields[2]));
                            break;
                        case 'd':
                            builder.addDnsServer(fields[1]);
                            break;
                        case 's':
                            builder.addSearchDomain(fields[1]);
                            break;
                        case 'n':
                            builder.setSession(fields[1]);
                            break;
                    }
                } catch (Exception e) {
                    throw new IllegalArgumentException("Bad parameter: " + parameter);
                }
            }

            ParcelFileDescriptor vpnInterface = builder.establish();
            if (vpnInterface != null) Log.i(TAG, "New interface: " + parameters);
            return vpnInterface;
        }
    }

    @Override
    public void onCreate() {
        // The handler is only used to show messages.
        if (mHandler == null) {
            mHandler = new Handler(Looper.myLooper(),this);
        }

        // Create the intent to "configure" the connection (just start ToyVpnClient).
        mConfigureIntent = PendingIntent.getActivity(this, 0, new Intent(this, StartActivity.class),
                PendingIntent.FLAG_UPDATE_CURRENT);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Become a foreground service. Background services can be VPN services too, but they can
        // be killed by background check before getting a chance to receive onRevoke().
        updateForegroundNotification(R.string.connecting);
        mHandler.sendEmptyMessage(R.string.connecting);

        if (mRunner != null)
            mRunner.stop();
        String serverSockName = intent.getStringExtra("SOCKNAME");
        if (serverSockName == null)
            serverSockName = DEFAULT_SOCKNAME;

        mRunner = new Runner(serverSockName);
        mRunner.start();
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        mHandler.sendEmptyMessage(R.string.disconnected);
        if (mRunner != null)
            mRunner.stop();
        stopForeground(true);
    }

    @Override
    public boolean handleMessage(Message message) {
        Toast.makeText(this, message.what, Toast.LENGTH_SHORT).show();
        if (message.what != R.string.disconnected) {
            updateForegroundNotification(message.what);
        }
        return true;
    }


    private void updateForegroundNotification(final int message) {
        // Oreo and later require a foreground persistent notification
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            final String NOTIFICATION_CHANNEL_ID = "VpnTether";
            NotificationManager mNotificationManager = (NotificationManager) getSystemService(
                    NOTIFICATION_SERVICE);
            mNotificationManager.createNotificationChannel(new NotificationChannel(
                    NOTIFICATION_CHANNEL_ID, NOTIFICATION_CHANNEL_ID,
                    NotificationManager.IMPORTANCE_DEFAULT));
            startForeground(1, new Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
                    .setSmallIcon(R.drawable.ic_vpn)
                    .setContentText(getString(message))
                    .setContentIntent(mConfigureIntent)
                    .build());
        }
    }

    // JNI Forwarding interface
    private static native int forward(int control, int stream, int datagram);
}