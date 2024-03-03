package big.pimpin.go2sleephoe;

public class DccActivity extends BaseSshActivity {
    public DccActivity() {
        super("winddcutil.exe setvcp 1 0x60 15");
    }
}
