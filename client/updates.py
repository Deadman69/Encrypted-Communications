# Minimal, privacy-friendly GitHub Releases checker.
# Accepts either "owner/repo" or a full "https://github.com/owner/repo" URL.

from __future__ import annotations
from typing import Optional, Tuple, List, Dict, Callable
import platform
import re
import webbrowser
from tkinter import messagebox

def _semver_tuple(v: str) -> Tuple[int, int, int, str]:
    """Parse 'v1.2.3' or '1.2.3' into a comparable tuple; non-semver -> (0,0,0,"")."""
    if not isinstance(v, str):
        return (0, 0, 0, "")
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$", v.strip())
    if not m:
        return (0, 0, 0, "")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), "")

def _choose_asset_for_platform(assets: List[Dict]) -> Optional[str]:
    """
    Heuristic: pick a likely asset for current OS/arch based on filename.
    Suggested naming (adapt as you wish):
      EncryptedClient-windows-x64.exe
      EncryptedClient-linux-x86_64
      EncryptedClient-macos-universal.zip (or .dmg)
    """
    sys = platform.system().lower()
    arch = (platform.machine() or "").lower()
    scored: List[Tuple[int, str, str]] = []
    for a in assets or []:
        name = (a.get("name") or "").lower()
        url = a.get("browser_download_url")
        if not url:
            continue
        # crude OS score
        if "windows" in name or name.endswith(".exe"):
            s_os = 3 if sys == "windows" else 0
        elif "mac" in name or "darwin" in name or "osx" in name:
            s_os = 3 if sys in ("darwin", "mac", "macos") else 0
        elif "linux" in name:
            s_os = 3 if sys == "linux" else 0
        else:
            s_os = 1
        # crude arch score
        if any(k in name for k in ("arm64", "aarch64")):
            s_arch = 2 if ("arm" in arch or "aarch64" in arch) else 0
        elif any(k in name for k in ("x86_64", "x64", "amd64")):
            s_arch = 2 if any(k in arch for k in ("64", "x86_64", "amd64")) else 0
        else:
            s_arch = 1
        scored.append((s_os + s_arch, name, url))
    scored.sort(reverse=True)
    return scored[0][2] if scored else None

def _normalize_repo(repo: str) -> Tuple[str, str]:
    """
    Accepts:
      - 'owner/repo'
      - 'https://github.com/owner/repo' (any scheme, any trailing slash)
    Returns:
      - ('owner/repo', 'https://github.com/owner/repo')
    """
    s = (repo or "").strip()
    if not s:
        return "", ""
    # Full URL?
    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+?)(?:/|$)", s, re.IGNORECASE)
    if m:
        owner, name = m.group(1), m.group(2)
        return f"{owner}/{name}", f"https://github.com/{owner}/{name}"
    # Possibly pasted with protocol by mistake (defensive)
    s = re.sub(r"^https?://github\.com/", "", s, flags=re.IGNORECASE)
    # Slug owner/repo
    parts = s.split("/")
    if len(parts) >= 2 and parts[0] and parts[1]:
        owner, name = parts[0], parts[1]
        return f"{owner}/{name}", f"https://github.com/{owner}/{name}"
    return "", ""

def check_for_updates(
    root,
    http,
    tr: Callable[[str], str],
    *,
    current_version: str,
    github_repo: str,
    silent: bool = False
) -> Dict[str, str]:
    """
    Manual update check via GitHub Releases 'latest'.
    - No background polling; call this from a menu/button.
    - Returns a small dict describing the outcome.
    - 'github_repo' can be 'owner/repo' or a full GitHub URL.
    """
    owner_repo, web_repo_url = _normalize_repo(github_repo)
    if not owner_repo:
        if not silent:
            messagebox.showerror(tr("menu.help"), tr("update.error", err="Bad repo value"))
        return {"status": "error", "error": "bad_repo"}

    api_latest   = f"https://api.github.com/repos/{owner_repo}/releases/latest"
    releases_url = f"{web_repo_url}/releases/latest"

    try:
        r = http.get(api_latest, timeout=12)
        r.raise_for_status()
        j = r.json()
        latest_tag = j.get("tag_name") or ""
        latest_url = j.get("html_url") or releases_url
        assets = j.get("assets") or []

        cur = _semver_tuple(current_version)
        lat = _semver_tuple(latest_tag)

        if lat <= cur:
            if not silent:
                messagebox.showinfo(tr("menu.help"), tr("update.latest_is", version=current_version))
            return {"status": "up_to_date", "current": current_version, "latest": latest_tag}

        # Update available
        if messagebox.askyesno(tr("menu.help"),
                               tr("update.update_available", current=current_version, latest=latest_tag)):
            asset_url = _choose_asset_for_platform(assets)
            webbrowser.open(asset_url or latest_url)
        return {"status": "update_available", "current": current_version, "latest": latest_tag}

    except Exception as e:
        if not silent:
            messagebox.showerror(tr("menu.help"), tr("update.error", err=str(e)))
        return {"status": "error", "error": str(e)}
