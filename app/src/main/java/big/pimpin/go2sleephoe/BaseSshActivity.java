package big.pimpin.go2sleephoe;

import android.app.Activity;
import android.os.Bundle;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;

public class BaseSshActivity extends Activity {
    private final String sshCommand;
    public BaseSshActivity(final String sshCommand) {
        super();
        this.sshCommand = sshCommand;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        //Toast.makeText(this, "Wir suchen dich", Toast.LENGTH_LONG).show();

        final Thread thread = new Thread(() -> {
            try (final SSHClient ssh = new SSHClient(new SshjAndroidConfig2())) {
                ssh.setConnectTimeout(5000);
                ssh.setTimeout(5000);
                ssh.addHostKeyVerifier(new PromiscuousVerifier());
                ssh.connect(SshjAndroidConfig2.HOSTNAME, SshjAndroidConfig2.PORT);
                ssh.getSocket().setTcpNoDelay(true);
                ssh.authPublickey(SshjAndroidConfig2.USERNAME, MainApplication.privateKeyFile.getAbsolutePath());
                ssh.startSession().exec(sshCommand);
            } catch (final Throwable th) {
                throw new RuntimeException(th);
            }
        });
        thread.start();
        try {
            thread.join(10000);
        } catch (final Throwable ignored) {}

        finishAndRemoveTask();
        System.exit(0);
    }
}
