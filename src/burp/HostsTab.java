package burp;

import javax.swing.*;
import com.google.common.net.InetAddresses;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;

public class HostsTab implements ITab {
  private JPanel panel;

  private JTextArea output;
  private JButton reload;

  PrintWriter stdout;
  PrintWriter stderr;

  public HostsTab(IBurpExtenderCallbacks callbacks) {
    this.stdout = new PrintWriter(callbacks.getStdout(), true); // for normal console output
    this.stderr = new PrintWriter(callbacks.getStderr(), true); // for error console output

    // Set up the panel
    this.panel = new JPanel();
    this.panel.setLayout(new BorderLayout());

    reload = new JButton();
    reload.setAction(new AbstractAction() {
      @Override
      public void actionPerformed(ActionEvent arg) {
        try {
          var hosts = readHostsFile();

          var string = "";
          for (Map.Entry<String, String> set : hosts.entrySet()) {

            // Printing all elements of a Map
            string += (set.getKey() + " = "
                + set.getValue()) + "\n";
          }

          ObjectMapper mapper = new ObjectMapper();
          HashMap<String, Object> jsonObject = new HashMap<>();
          jsonObject.put("project_options.connections.hostname_resolution", hosts.entrySet().stream()
                  .map(e -> {
                      HashMap<String, Object> obj = new HashMap<>();
                      obj.put("enabled", true);
                      obj.put("hostname", e.getKey());
                      obj.put("ip_address", e.getValue());
                      return obj;
                  })
                  .toArray());

          callbacks.loadConfigFromJson(mapper.writeValueAsString(jsonObject));

          output.setText("Added the following hosts:\n\n" + string);
        } catch (IOException error) {
          output.setText("Failed to load hosts file");
        }

      }
    });
    reload.setPreferredSize(new Dimension(500, 25));
    reload.setText("Reload Hosts");

    this.panel.add(reload, BorderLayout.PAGE_START);

    // Add a label to the panel
    output = new JTextArea("Output");
    this.panel.add(output, BorderLayout.CENTER);
  }

  @Override
  public String getTabCaption() {
    return "Hosts Loader";
  }

  @Override
  public Component getUiComponent() {
    return this.panel;
  }

  public Map<String, String> readHostsFile() throws IOException {
    Map<String, String> hostsMap = new HashMap<>();
    BufferedReader br = null;
    String hostsFilePath = null;

    stdout.println("loading hosts");

    // Check if the OS is Windows or Linux
    String osName = System.getProperty("os.name").toLowerCase();
    if (osName.contains("win")) {
      hostsFilePath = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    } else {
      hostsFilePath = "/etc/hosts";
    }

    try {
      br = new BufferedReader(new FileReader(hostsFilePath));
      String line;
      while ((line = br.readLine()) != null) {
        line = line.trim();
        if (!line.startsWith("#") && !line.isEmpty()) {
          String[] tokens = line.split("\\s+");
          String ip = tokens[0];
          stdout.println(ip);
          if (!InetAddresses.isInetAddress(ip)) {
            continue;
          }

          for (int i = 1; i < tokens.length; i++) {
            String hostname = tokens[i];
            hostsMap.put(hostname, ip);
          }
        }
      }
    } catch (IOException e) {
      // If the hosts file is not found, return an empty map
      return hostsMap;
    } finally {
      if (br != null) {
        br.close();
      }
    }

    return hostsMap;
  }
}
