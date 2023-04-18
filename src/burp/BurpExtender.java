package burp;

import java.awt.Component;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {
    //
    // implement IBurpExtender
    //
    PrintWriter stdout;
    PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // set our extension name
        callbacks.setExtensionName("Hosts Loader");
        this.stdout = new PrintWriter(callbacks.getStdout(), true); // for normal console output
        this.stderr = new PrintWriter(callbacks.getStderr(), true); // for error console output
        callbacks.addSuiteTab(new HostsTab(callbacks));
        
        stdout.println("Hosts Loader loaded");
    }
}
