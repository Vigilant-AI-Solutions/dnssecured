(() => {
  const nodes = Array.from(document.querySelectorAll(".node"));
  if (nodes.length === 0) return;

  const stageEl = document.getElementById("telemetry-stage");
  const scoreEl = document.getElementById("telemetry-score");
  const routeEl = document.getElementById("telemetry-route");

  const stages = [
    { name: "Query Ingest", score: 100, route: "pending" },
    { name: "Trusted Resolver", score: 98, route: "resolver: dot-primary" },
    { name: "Security Checks", score: 94, route: "checks: policy pass" },
    { name: "DNSSEC + DANE", score: 92, route: "dnssec: validated" },
    { name: "Traffic Steering", score: 92, route: "us-east-1" },
  ];

  let index = 0;
  const cycle = () => {
    nodes.forEach((n) => n.classList.remove("active"));
    nodes[index].classList.add("active");

    const stage = stages[index];
    if (stageEl) stageEl.textContent = stage.name;
    if (scoreEl) scoreEl.textContent = String(stage.score);
    if (routeEl) routeEl.textContent = stage.route;

    index = (index + 1) % stages.length;
  };

  cycle();
  window.setInterval(cycle, 1400);
})();
