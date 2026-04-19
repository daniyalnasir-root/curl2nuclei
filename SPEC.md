name: curl2nuclei
purpose: Convert a real curl command into a runnable nuclei YAML detection template, so a one-off manual probe becomes a repeatable scan in one step.
actionable_payoff: Writes a complete, valid nuclei YAML to disk (or stdout) that the user immediately runs with `nuclei -t out.yaml -u <target>` — printed verbatim at the end of every run as the "next step" panel. No table to read; an artifact to execute.
language: python
why_language: shlex + argparse + a tiny YAML emitter cover the whole job from stdlib + PyYAML; easier curl tokenisation in Python than Go.
features:
- Parses real curl strings (multi-line, -H, -X, -d/--data-raw, --cookie, -u, -G query)
- Six vuln-class profiles: sqli, ssrf, xss, redirect, rce, time-based
- OOB classes auto-inject `{{interactsh-url}}` and add `interactsh_protocol` matchers
- Inline classes inject payload lists with regex/word matchers tuned per class
- Pinpoints the parameter to fuzz with `--param name`; otherwise marks every query/body param `§§`
- Emits a `# next:` panel at the bottom with the exact `nuclei -t ... -u ...` command
input_contract: a curl command (string or @file) and a vuln class flag
output_contract: a nuclei YAML template (stdout or --out path) plus a boxed next-step callout
output_style: yaml-body-plus-box-panel — no tables, no `---` dividers; uses Unicode box-drawing for the next-step block. Visibly distinct from scopesift's wide ASCII table and email-atom's variant×parser grid.
safe_test_target: httpbin.org/anything (GET with ?id=) and httpbin.org/anything (GET with ?url=)
synonym_names:
- curl2yaml
- mintplate
- nuclei-mint
source_inspiration_url: https://docs.projectdiscovery.io/templates/structure
