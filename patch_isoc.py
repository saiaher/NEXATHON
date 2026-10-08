# patch_isoc.py — OPTIONAL. Only needed if you want to patch your OWN older copy of the dashboard.
# (The ISOC_v6.py I gave you is already patched — you do NOT need to run this on it.)
#   python patch_isoc.py                # patches ISOC_v6.py
#   python patch_isoc.py my_file.py
# Safe to run many times. Makes a backup (<file>.bak).
import re, sys, shutil

path = sys.argv[1] if len(sys.argv) > 1 else "ISOC_v6.py"
src = open(path, encoding="utf-8").read()
shutil.copy(path, path + ".bak")
done = []

# 0) remove leftovers from older versions of the agent
src = src.replace("from isoc_agent import render_agent_sidebar\n", "")
src = re.sub(r"[ \t]*render_agent_sidebar\(\)[ \t]*\n", "", src)

# 1) import
if "from isoc_agent import render_agent_panel" not in src:
    src, n = re.subn(r"(import plotly\.graph_objects as go[^\n]*\n)",
                     r"\1from isoc_agent import render_agent_panel   # ISOC Assistant\n", src, count=1)
    done.append("import added" if n else "!! import NOT added (plotly import line not found)")
else:
    done.append("import already present")

# 2) call as the first line of main()
if not re.search(r"^\s+render_agent_panel\(\)", src, re.M):
    src, n = re.subn(r"(\ndef main\(\):\n)", r"\1    render_agent_panel()   # floating chat button\n", src, count=1)
    done.append("chat call added" if n else "!! chat call NOT added (def main() not found)")
else:
    done.append("chat call already present")

# 3) fix StreamlitDuplicateElementId on the hop chart
old = "st.plotly_chart(fig, use_container_width=True)\n\ndef render_ip_drilldown"
new = 'st.plotly_chart(fig, use_container_width=True, key=f"hop_chart_{ia.ip}_{id(ia)}")\n\ndef render_ip_drilldown'
if old in src:
    src = src.replace(old, new, 1); done.append("plotly duplicate-key fixed")
else:
    done.append("plotly key: already fixed / not found")

open(path, "w", encoding="utf-8").write(src)
print(f"Patched {path} (backup: {path}.bak)")
for d in done: print(" -", d)