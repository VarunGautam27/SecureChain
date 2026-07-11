# SecureChain GUI guide

A local preview application for SecureChain. It runs entirely on your own
machine and never replaces the CI/CD gate. A push still triggers the same
GitHub Actions workflow, and that run remains the only result that actually
blocks a merge. The GUI exists to remove the need to open a terminal or a
separate report file while you review and fix flagged dependencies.

## Starting it

```bash
pip install -e .
securechain gui
```

This opens `http://127.0.0.1:5678` in your default browser automatically. To
stop it, return to the terminal and press Control C.

If you prefer running the script directly instead of the installed command:

```bash
python scripts/run_gui.py
```

## Using it, step by step

1. **Select a project folder.** Click Browse to open a native folder picker,
   or type a path directly into the field. Any `package.json` (npm) or
   `requirements.txt` (Python/PyPI) inside that folder or one of its
   subfolders is found automatically, so pointing at a whole project root
   works even if the manifest itself sits a level or two down (for example
   this repository's own `demo/package.json` and `demo/requirements.txt`).
   If more than one is found, a dropdown lets you pick which one to scan.
2. **Scan.** Once a valid folder is detected, the Scan button becomes active.
   Clicking it runs the exact same pipeline the CI gate uses: the same CVE
   lookup, the same exploit intelligence lookup, the same behavioral feature
   extraction, the same Random Forest and Isolation Forest scoring, and the
   same SHAP explanations. If your project also has a `demo/fixtures` folder
   (only the case for this repository's own demo), a checkbox lets you reuse
   that cached data for a fast result with no network calls. For a real
   project, leave that checkbox unchecked so the scan hits live data exactly
   as a CI run would. If a `package-lock.json` sits next to the manifest, a
   second checkbox appears, "Also scan transitive dependencies", scanning
   everything the lockfile actually resolves, not only what `package.json`
   names directly.
3. **Read the result.** A banner at the top states whether the current folder
   would pass or fail the gate right now, followed by the same severity
   tiers, filter buttons, and per dependency tabs (Recommendation, CVSS,
   Severity, Behavioral) as the static HTML report. Severity colors are the
   same fixed five step scale used everywhere else in this project.
4. **Fix or accept, per flagged dependency.** The Recommendation tab shows an
   Apply Upgrade button whenever a fixed version exists, writing that
   version straight into the manifest, then rescanning automatically. If you
   would rather record a deliberate exception instead, each flagged card has
   an Accept Risk box right there, a reason and a name, calling the same
   `securechain accept` logic under the hood and writing to
   `.riskignore.json` in that folder.
5. **Push.** The Push button stages only the manifest you scanned and
   `.riskignore.json` if it exists, never every changed file in the folder,
   then commits and pushes. It uses whatever git credentials are already
   configured on your machine. No separate login is requested anywhere in
   this application. If the folder's remote points somewhere else than
   where you want to push, the Remote repository field above it shows the
   current one and lets you set a different one, for a different project
   or a different GitHub account, before pushing. Setting a remote on a
   folder that isn't a git repository yet runs git init first.
6. **Watch the CI result.** After a push, a status pill polls GitHub's public
   status for your latest commit every few seconds and shows pending,
   passed, or failed, without needing to open github.com. This works without
   a login too, since it reads a public repository's status.
7. **Fix and push again.** If the result failed, edit `package.json` yourself
   (or accept the remaining risks), scan again to confirm locally, and push
   again. The loop repeats with no memory of the previous attempt, exactly
   like the CLI and CI already work.

## What this is not

It is not a second enforcement mechanism. The local pass or fail banner is a
preview of what the gate would decide right now, on your machine, with
whatever data was reachable at that moment. Only the GitHub Actions run
triggered by an actual push is authoritative, since only that run is what
your branch protection rules (if configured) actually check before allowing
a merge.

## Requirements

Flask is used for the local server and is already listed in
`requirements.txt` and `pyproject.toml`. The native folder picker uses
Tkinter, part of the Python standard library on Windows and most desktop
Python installations. If no display is available to show that dialog, the
GUI falls back to typing a path by hand.
