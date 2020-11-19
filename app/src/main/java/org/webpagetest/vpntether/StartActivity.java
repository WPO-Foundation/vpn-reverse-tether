package org.webpagetest.vpntether;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.util.Log;

/**
 * Launcher for TetherService. Needed to acquire the BIND_VPN_SERVICE
 * permission.
 *
 * @author szym@google.com (Szymon Jakubczak)
 */
public class StartActivity extends Activity {
    private String mServerSockName;
    private static final String TAG = StartActivity.class.getSimpleName();

    @Override
    public void onCreate(Bundle savedInstanceState) {
        Log.d(TAG, "onCreate");
        super.onCreate(savedInstanceState);
        mServerSockName = getIntent().getStringExtra("SOCKNAME");
        Log.d(TAG, "Socket name: " + mServerSockName);

        Intent intent = VpnService.prepare(this);

        if (intent != null) {
            Log.d(TAG, "VPN service prepared");
            startActivityForResult(intent, 0);
        } else {
            onActivityResult(0, RESULT_OK, null);
        }
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        int message = R.string.result_fail_prepare;
        if (result == RESULT_OK) {
            Intent intent = new Intent(this, TetherService.class)
                    .putExtra("SOCKNAME", mServerSockName);
            message = (startService(intent) != null) ?
                    R.string.result_success : R.string.result_fail_start;
        }
        new AlertDialog.Builder(this)
                .setTitle(R.string.app_name)
                .setMessage(message)
                .setOnCancelListener(new DialogInterface.OnCancelListener() {
                    @Override
                    public void onCancel(DialogInterface dialog) {
                        finish();
                    }
                })
                .create()
                .show();
    }
}
