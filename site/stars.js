(() => {
  const target = document.getElementById("github-stars");
  if (!target) return;

  const formatStars = (n) => {
    if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
    return String(n);
  };

  fetch("https://api.github.com/repos/Vigilant-AI-Solutions/dnssecured", {
    headers: { Accept: "application/vnd.github+json" },
  })
    .then((r) => {
      if (!r.ok) throw new Error(`GitHub API ${r.status}`);
      return r.json();
    })
    .then((repo) => {
      const stars = Number(repo.stargazers_count || 0);
      target.textContent = `★ ${formatStars(stars)} stars`;
    })
    .catch(() => {
      target.textContent = "★ GitHub stars";
    });
})();
