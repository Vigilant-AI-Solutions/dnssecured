(() => {
  const output = document.getElementById("terminal-output");
  const input = document.getElementById("terminal-input");
  if (!output || !input) return;

  const steps = [
    {
      cmd: "cat > DNSsecuredfile << 'EOF'",
      lines: [
        "listen :8080",
        "resolver_mode dot",
        "dot_upstreams 1.1.1.1 1.0.0.1",
        "checks ns_redundancy dnssec_validation dane_tlsa tls_certificate dmarc",
        "default_tenant demo-team",
        "EOF",
        "2026/05/09 15:09:01.102 INFO    file written           {\"path\":\"./DNSsecuredfile\"}",
      ],
    },
    {
      cmd: "dnssecured validate --config ./DNSsecuredfile",
      lines: [
        "2026/05/09 15:09:04.120 INFO    config loaded          {\"file\":\"./DNSsecuredfile\"}",
        "2026/05/09 15:09:04.469 INFO    resolver ready         {\"mode\":\"dot\",\"upstreams\":2}",
        "2026/05/09 15:09:04.918 INFO    checks ready           {\"count\":5}",
        "Config OK (./DNSsecuredfile)",
      ],
    },
    {
      cmd: "dnssecured run --config ./DNSsecuredfile --addr :8080",
      lines: [
        "2026/05/09 15:09:08.011 INFO    dnssecured listening    {\"addr\":\":8080\",\"resolver_mode\":\"dot\"}",
        "2026/05/09 15:09:09.315 INFO    pipeline stage          {\"stage\":\"resolver_trust\",\"upstream\":\"1.1.1.1:853\"}",
        "2026/05/09 15:09:10.644 INFO    pipeline stage          {\"stage\":\"dnssec_validation\",\"status\":\"pass\"}",
        "2026/05/09 15:09:11.936 INFO    pipeline stage          {\"stage\":\"dane_tlsa\",\"status\":\"pass\"}",
        "2026/05/09 15:09:13.214 INFO    steering decision       {\"route\":\"us-east-1\",\"latency_ms\":21}",
      ],
    },
    {
      cmd: "curl -sS http://localhost:8080/v1/analyze -d '{\"domain\":\"example.com\"}'",
      lines: [
        "2026/05/09 15:09:16.020 INFO    request accepted       {\"tenant\":\"demo-team\",\"domain\":\"example.com\"}",
        "{\"posture_score\":92,\"summary\":{\"passed\":7,\"warned\":2,\"failed\":0,\"errored\":0}}",
      ],
    },
    {
      cmd: "sudo systemctl restart dnssecured && sudo systemctl status dnssecured --no-pager",
      lines: [
        "● dnssecured.service - DNSsecured API",
        "   Active: active (running) since Sat 2026-05-09 15:09:22 UTC; 4s ago",
      ],
    },
    {
      cmd: "# This is a demo of writing config, validating, and deploying DNSsecured.",
      lines: [],
    },
    {
      cmd: "# Tune DNSsecuredfile and rerun validate before each rollout.",
      lines: [],
    },
    {
      cmd: "# Thanks for watching :)",
      lines: ["Watch in real-time as DNSsecured secures DNS posture with a config-first workflow."],
    },
  ];

  const pause = (ms) => new Promise((resolve) => window.setTimeout(resolve, ms));

  const appendLine = (line) => {
    output.textContent += `${line}\n`;
    output.scrollTop = output.scrollHeight;
  };

  const typeCommand = async (cmd) => {
    input.textContent = "";
    for (const ch of cmd) {
      input.textContent += ch;
      await pause(38);
    }
    await pause(380);
    appendLine(`╔[dns@secured:~/demo]`);
    appendLine(`╚>$ ${cmd}`);
    input.textContent = "";
  };

  const run = async () => {
    output.textContent = "";
    while (true) {
      for (const step of steps) {
        await typeCommand(step.cmd);
        for (const line of step.lines) {
          appendLine(line);
          await pause(850);
        }
        appendLine("");
        await pause(1400);
      }
      await pause(2200);
      output.textContent = "";
    }
  };

  run();
})();
