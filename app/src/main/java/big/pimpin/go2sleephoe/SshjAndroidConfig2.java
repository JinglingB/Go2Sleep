package big.pimpin.go2sleephoe;

import com.hierynomus.sshj.key.KeyAlgorithms;

import net.schmizz.sshj.DefaultConfig;

import java.util.Arrays;

class SshjAndroidConfig2 extends DefaultConfig {
    static final String HOSTNAME = "192.168.1.1";
    static final int PORT = 22;
    static final String USERNAME = "toor";

    @Override
    protected void initKeyAlgorithms() {
        setKeyAlgorithms(Arrays.asList(
                KeyAlgorithms.EdDSA25519(),
                KeyAlgorithms.SSHRSA(),
                KeyAlgorithms.SSHDSA()
        ));
    }
}
