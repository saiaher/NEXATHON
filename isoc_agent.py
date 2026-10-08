# isoc_agent.py — ISOC Assistant: floating ChatGPT-style chat (Groq, streaming)
# Needs: pip install -U streamlit     (no other package)
#
# >>> PASTE YOUR NEW GROQ KEY BELOW (never share it / never commit it) <<<
import os
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("GROQ_API_KEY")#   or set env var GROQ_API_KEY / st.secrets["GROQ_API_KEY"]
#
# Works with or without a domain analysed. Models are auto-discovered from your Groq
# account (so a retired model name can never cause HTTP 404 again).

import os, json, urllib.request, urllib.error
import streamlit as st
import streamlit.components.v1 as components

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MODELS_URL = "https://api.groq.com/openai/v1/models"
UA = "jio-isoc-agent/4.0"
FALLBACK_MODELS = ["llama-3.3-70b-versatile", "openai/gpt-oss-20b", "llama-3.1-8b-instant"]
MAX_OUT = 700
HISTORY_MSGS = 8

SYSTEM = (
    "You are ISOC Assistant inside Jio's internal network operations dashboard. "
    "Act like a helpful ChatGPT-style assistant: answer ANY question clearly (networking, DNS, BGP, "
    "troubleshooting, or general topics) and reply in the user's language (English, Hindi or Hinglish). "
    "For network problems give: likely cause, then numbered fix steps. If DASHBOARD DATA is present and "
    "relevant, use it and never invent data that is not in it; if no analysis has been run, still answer "
    "from general knowledge. Be concise; use short markdown."
)

QUICK = [("🌐 DNS failing?", "Why does DNS resolution fail and how do I fix it?"),
         ("📉 Packet loss", "What causes packet loss and how do I troubleshoot it?"),
         ("🛡️ RPKI / IRR", "Explain RPKI Invalid and missing IRR and the fix."),
         ("🐢 High latency", "How do I find the cause of high latency in a traceroute?")]

KB = [
    (("nxdomain", "not exist", "unresolvable"), "Domain does not exist or DNS can't resolve it.",
     "Check spelling; try another DNS profile; verify NS delegation at the registrar."),
    (("timeout", "servfail", "dns"), "DNS server did not answer in time.",
     "Try the secondary server; check UDP/TCP 53 and IPv6 reachability; compare with public DNS."),
    (("packet loss", "loss", "drop"), "Packets are dropped on the path.",
     "Find the first hop where loss starts; last-hop-only loss is usually target firewall/ICMP limit; mid-path loss -> ticket to that hop's ASN owner."),
    (("latency", "slow", "spike", "bottleneck", "rtt"), "High or rising latency at a hop.",
     "Check the bottleneck hop and its ASN; a 50ms+ jump often means long-haul/peering congestion."),
    (("irr", "rpki", "route leak", "invalid", "hijack"), "Missing IRR object or RPKI Invalid/NotFound.",
     "Owner should fix route objects/ROAs; for Invalid check origin ASN and maxLength."),
    (("blocked", "block"), "Matched the hardcoded block rule.",
     "Confirm the block is intended; otherwise review the block-list/DNS sinkhole."),
    (("ssh", "ibr", "jump", "paramiko"), "SSH to Jump Server/IBR failed.",
     "Check IP/port 22, credentials, ACLs, paramiko install; SSH timeout is 3s."),
    (("traceroute", "hop", "star"), "Hops not responding (* * *).",
     "Usually ICMP filtering, not an outage. Run as root or install traceroute."),
    (("nat64", "synthetic", "ipv6"), "NAT64 address synthesized (64:ff9b::/96) from IPv4.",
     "Verify DNS64/NAT64 gateway for IPv6-only (5G) users."),
]


# ── dashboard facts / context ─────────────────────────────────
def _facts(r):
    f = []
    if getattr(r, "health", "") == "BLOCKED":
        f.append("BLOCKED: matched hardcoded block rule")
    if not r.valid:
        f.append(f"DNS FAIL: {r.invalid_reason}")
        return f
    for ia in r.ip_analyses:
        t = ia.ip
        if not ia.ping_ok:
            f.append(f"{t}: unreachable")
        elif ia.packet_loss > 0:
            f.append(f"{t}: {ia.packet_loss:.0f}% loss")
        if ia.bottleneck_hop:
            hp = [h for h in ia.hops if h.num == ia.bottleneck_hop]
            if hp and hp[0].is_anomaly:
                f.append(f"{t}: hop {hp[0].num} {hp[0].ip} {hp[0].anomaly_reason}")
        stars = sum(1 for h in ia.hops if h.ip == "*")
        if stars > 3:
            f.append(f"{t}: {stars} silent hops")
        if ia.asn_info:
            if not ia.asn_info.irr_valid:
                f.append(f"{t}: AS{ia.asn_info.asn} IRR missing")
            if ia.asn_info.rpki == "Invalid":
                f.append(f"{t}: AS{ia.asn_info.asn} RPKI Invalid")
        if "SSH Exception" in (ia.ibr_raw or ""):
            f.append(f"{t}: IBR SSH failed")
    if "SSH Exception" in (r.jump_raw or ""):
        f.append("Jump server SSH failed")
    return f


def _context(reports, sel):
    if not reports:
        return "No analysis has been run yet."
    L = ["DOMAINS:"]
    for x in reports[:15]:
        st_ = f"invalid({x.invalid_reason})" if not x.valid else x.health
        L.append(f"- {x.domain}: {st_}, {len(x.resolved_ips)} IPs")
    r = next((x for x in reports if x.domain == sel), None)
    if r:
        L.append(f"SELECTED: {r.domain} | DNS {r.dns_profile} via {r.dns_server_used}")
        for ia in r.ip_analyses[:6]:
            a = ia.asn_info
            L.append(f"  {ia.ip} v{ia.ip_version}{' nat64' if ia.is_synthetic_v6 else ''}: "
                     f"loss {ia.packet_loss:.0f}%, avg {ia.avg_latency:.0f}ms, hops {len(ia.hops)}, "
                     f"AS{ia.peer_asn} {a.org if a else ''}, irr {a.irr_valid if a else '?'}, "
                     f"rpki {a.rpki if a else '?'}")
        fx = _facts(r)
        L.append("ISSUES: " + ("; ".join(fx[:8]) if fx else "none"))
    return "\n".join(L)[:1500]


# ── Groq (auto model discovery + streaming) ───────────────────
def _get_key():
    if GROQ_API_KEY.strip():
        return GROQ_API_KEY.strip()
    k = os.environ.get("GROQ_API_KEY")
    if k:
        return k
    try:
        return st.secrets.get("GROQ_API_KEY", "")
    except Exception:
        return ""


def _models(key):
    cached = st.session_state.get("agent_models")
    if cached:
        return cached
    ids = []
    try:
        req = urllib.request.Request(MODELS_URL, headers={"Authorization": f"Bearer {key}", "User-Agent": UA})
        with urllib.request.urlopen(req, timeout=10) as resp:
            ids = [m["id"] for m in json.loads(resp.read().decode()).get("data", [])
                   if m.get("active", True)]
    except Exception:
        pass
    bad = ("whisper", "guard", "tts", "playai", "orpheus", "embed", "safeguard", "allam", "compound")
    ids = [i for i in ids if not any(b in i.lower() for b in bad)]
    pref = ("llama-3.3-70b", "gpt-oss-120b", "llama-4", "gpt-oss-20b", "llama-3.1-8b", "qwen", "kimi", "gemma")

    def rank(i):
        for n, p in enumerate(pref):
            if p in i.lower():
                return n
        return 99
    ids = sorted(ids, key=rank)[:5]
    if ids:
        st.session_state.agent_models = ids
        return ids
    return FALLBACK_MODELS


def _gen(msgs, key, info):
    """Streams answer chunks; records last error in info['err']."""
    if not key:
        info["err"] = "No Groq key set — add it on line 6 of isoc_agent.py"
        return
    for m in _models(key):
        got = False
        try:
            body = json.dumps({"model": m, "messages": msgs, "max_tokens": MAX_OUT,
                               "temperature": 0.3, "stream": True}).encode()
            req = urllib.request.Request(GROQ_URL, data=body, headers={
                "Authorization": f"Bearer {key}", "Content-Type": "application/json", "User-Agent": UA})
            with urllib.request.urlopen(req, timeout=40) as resp:
                for raw in resp:
                    line = raw.decode("utf-8", "ignore").strip()
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        return
                    try:
                        delta = json.loads(data)["choices"][0]["delta"].get("content")
                    except Exception:
                        continue
                    if delta:
                        if not got:
                            got = True
                            info["ph"].empty()          # remove typing dots
                        yield delta
            if got:
                return
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = json.loads(e.read().decode())["error"]["message"][:140]
            except Exception:
                pass
            info["err"] = f"HTTP {e.code} {detail}".strip()
            if e.code in (401, 403):
                info["err"] += " — check/create a new Groq key"
                return
        except Exception as e:
            info["err"] = f"{type(e).__name__}: {str(e)[:100]}"
            if got:
                return


def _kb_answer(q, facts, err):
    ql = q.lower()
    hits = [(p, s) for ks, p, s in KB if any(k in ql for k in ks)][:2]
    ans = ""
    if hits:
        ans = "\n\n".join(f"**Problem:** {p}\n\n**Fix:** {s}" for p, s in hits)
        if facts:
            ans += "\n\n_This domain:_ " + "; ".join(facts[:3])
    return (ans + "\n\n" if ans else "") + f"⚠️ _AI not reachable: {err or 'unknown error'}_"


# ── chat UI ───────────────────────────────────────────────────
_TYPING = ('<div class="agent-typing"><span></span><span></span><span></span></div>')


def _chat_body():
    reports = st.session_state.get("reports", [])
    sel = st.session_state.get("selected")
    r = next((x for x in reports if x.domain == sel), None)
    hist = st.session_state.setdefault("agent_hist", [])
    facts = _facts(r) if r else []
    pending = st.session_state.pop("agent_pending", None)

    box = st.container(height=370, border=False)

    if not hist and not pending:
        qa = st.columns(2)
        for i, (label, prompt) in enumerate(QUICK):
            if qa[i % 2].button(label, key=f"agent_quick{i}", use_container_width=True):
                st.session_state.agent_pending = prompt
                st.rerun()

    with st.form("agent_form", clear_on_submit=True, border=False):
        f1, f2 = st.columns([6, 1], vertical_alignment="center")
        q = f1.text_input("Message", label_visibility="collapsed", placeholder="Message")
        send = f2.form_submit_button("➤", use_container_width=True)
    if hist and st.button("＋ New chat", key="agent_clear"):
        hist.clear()
        st.rerun()

    question = pending or (q.strip() if send and q.strip() else None)

    with box:
        if not hist and not question:
            st.markdown('<div class="agent-empty"><div class="agent-empty-ico">🤖</div>'
                        '<div class="agent-empty-t">How can I help?</div></div>', unsafe_allow_html=True)
            if facts:
                with st.chat_message("assistant", avatar="🤖"):
                    st.markdown("**Issues found for this domain:**\n" +
                                "\n".join(f"- ⚠️ {f}" for f in facts[:6]))
        for m in hist[-20:]:
            with st.chat_message(m["role"], avatar="🤖" if m["role"] == "assistant" else None):
                st.markdown(m["content"])
        if question:
            with st.chat_message("user"):
                st.markdown(question)
            with st.chat_message("assistant", avatar="🤖"):
                ph = st.empty()
                ph.markdown(_TYPING, unsafe_allow_html=True)
                info = {"ph": ph, "err": ""}
                msgs = [{"role": "system", "content": SYSTEM + "\n\nDASHBOARD DATA:\n" + _context(reports, sel)}]
                msgs += hist[-HISTORY_MSGS:]
                msgs.append({"role": "user", "content": question})
                g = _gen(msgs, _get_key(), info)
                ans = st.write_stream(g) if hasattr(st, "write_stream") else "".join(g)
                if not (ans or "").strip():
                    ph.empty()
                    ans = _kb_answer(question, facts, info["err"])
                    st.markdown(ans)
            hist.append({"role": "user", "content": question})
            hist.append({"role": "assistant", "content": ans})


_PANEL_CSS = """
<style>
.st-key-agent_box {
    display: none; position: fixed; bottom: 100px; right: 30px; width: 440px; max-width: 94vw;
    max-height: 86vh; overflow-y: auto; z-index: 999998; gap: 0 !important;
    background: #ffffff; border: 1px solid #e2e8f0; border-radius: 20px;
    box-shadow: 0 20px 60px rgba(15,23,42,0.28);
}
body.jio-agent-open .st-key-agent_box { display: block; }
.st-key-agent_inner { padding: 6px 14px 12px; }
.agent-hdr { display:flex; align-items:center; gap:12px; padding:14px 16px; color:#fff;
    background: linear-gradient(135deg,#0B58C6,#6d5ef0); }
.agent-logo { width:42px; height:42px; border-radius:50%; background:rgba(255,255,255,.22);
    display:flex; align-items:center; justify-content:center; font-size:23px; }
.agent-title { font-weight:800; font-size:1.02rem; letter-spacing:.2px; line-height:1.2; }
.agent-sub { font-size:.72rem; opacity:.92; display:flex; align-items:center; gap:6px; }
.agent-dot { width:8px; height:8px; border-radius:50%; background:#4ade80; display:inline-block; }
.agent-close { margin-left:auto; cursor:pointer; font-size:1.2rem; width:32px; height:32px; border-radius:50%;
    display:flex; align-items:center; justify-content:center; background:rgba(255,255,255,.15); }
.agent-close:hover { background:rgba(255,255,255,.3); }
.agent-empty { text-align:center; padding:2.2rem 0 1rem; }
.agent-empty-ico { font-size:2.6rem; }
.agent-empty-t { font-size:1.15rem; font-weight:700; color:#0f172a; margin-top:.4rem; }
/* bubbles */
.st-key-agent_box [data-testid="stChatMessage"] { width: fit-content; max-width: 92%;
    background: #f1f5f9; border-radius: 4px 16px 16px 16px; padding: .55rem .85rem;
    margin-bottom: .35rem; font-size: .9rem; color:#0f172a; }
.st-key-agent_box [data-testid="stChatMessage"] * { color:#0f172a; }
.st-key-agent_box [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]) {
    margin-left: auto; flex-direction: row-reverse; border-radius: 16px 4px 16px 16px;
    background: linear-gradient(135deg,#0B58C6,#6d5ef0); }
.st-key-agent_box [data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]) * { color:#fff !important; }
.st-key-agent_box [data-testid="stChatMessageAvatarUser"] { display:none; }
/* input pill + send */
.st-key-agent_box div[data-testid="stTextInput"] input { border-radius: 24px !important;
    padding: .65rem 1rem !important; background:#f1f5f9 !important; border:1px solid #e2e8f0 !important;
    color:#0f172a !important; }
.st-key-agent_box [data-testid="stFormSubmitButton"] button { border-radius: 50% !important;
    width: 44px !important; height: 44px !important; padding: 0 !important; font-size: 1.1rem !important;
    background: linear-gradient(135deg,#0B58C6,#6d5ef0) !important; color:#fff !important; }
.st-key-agent_box [data-testid="stForm"] { border:none !important; padding:0 !important; }
/* quick chips + new chat */
.st-key-agent_box .stButton button { border-radius: 14px !important; font-size:.8rem !important;
    padding:.45rem .6rem !important; letter-spacing:0 !important; }
/* typing dots */
.agent-typing { display:flex; gap:5px; padding:.3rem 0; }
.agent-typing span { width:8px; height:8px; border-radius:50%; background:#94a3b8; animation: agentb 1.2s infinite; }
.agent-typing span:nth-child(2) { animation-delay:.2s; } .agent-typing span:nth-child(3) { animation-delay:.4s; }
@keyframes agentb { 0%,60%,100% { transform:translateY(0); opacity:.4; } 30% { transform:translateY(-5px); opacity:1; } }
</style>
"""

# Runs in the parent page (same technique as the Pipeline widget): round 🤖 toggle button
_AGENT_JS = """
(function(){
  if (document.getElementById('jio-agent-fab')) return;
  var fab = document.createElement('div');
  fab.id = 'jio-agent-fab'; fab.title = 'ISOC Assistant'; fab.textContent = '🤖';
  fab.style.cssText = 'position:fixed;bottom:30px;right:100px;z-index:999999;width:58px;height:58px;' +
    'border-radius:50%;background:linear-gradient(135deg,#0B58C6,#6d5ef0);' +
    'box-shadow:0 8px 24px rgba(11,88,198,0.4);cursor:pointer;display:flex;align-items:center;' +
    'justify-content:center;color:#fff;font-size:26px;user-select:none;transition:transform .2s ease;';
  fab.onmouseover = function(){ fab.style.transform = 'scale(1.07)'; };
  fab.onmouseout  = function(){ fab.style.transform = 'scale(1)'; };
  function place(){
    var p = document.querySelector('.st-key-agent_box'); if (!p) return;
    var r = fab.getBoundingClientRect(), W = window.innerWidth, H = window.innerHeight;
    p.style.left = 'auto'; p.style.right = Math.max(8, W - r.right) + 'px';
    if (r.top > H / 2) { p.style.top = 'auto'; p.style.bottom = (H - r.top + 12) + 'px'; p.style.maxHeight = (r.top - 24) + 'px'; }
    else { p.style.bottom = 'auto'; p.style.top = (r.bottom + 12) + 'px'; p.style.maxHeight = (H - r.bottom - 24) + 'px'; }
  }
  fab.onclick = function(){ document.body.classList.toggle('jio-agent-open'); place(); };
  document.addEventListener('click', function(e){
    if (e.target.closest && e.target.closest('.agent-close')) document.body.classList.remove('jio-agent-open');
  });
  window.addEventListener('resize', place);
  setInterval(function(){ if (document.body.classList.contains('jio-agent-open')) place(); }, 400);
  document.body.appendChild(fab);
})();
"""

_HEADER = ('<div class="agent-hdr"><div class="agent-logo">🤖</div><div>'
           '<div class="agent-title">ISOC Assistant</div>'
           '<div class="agent-sub"><span class="agent-dot"></span>Online · Jio Network Operations</div>'
           '</div><div class="agent-close">✕</div></div>')


def render_agent_panel():
    """Call at the start of main(). Adds the floating 🤖 toggle + chat panel."""
    st.markdown(_PANEL_CSS, unsafe_allow_html=True)
    components.html(
        "<script>var d=window.parent.document;if(!d.getElementById('jio-agent-js')){"
        "var s=d.createElement('script');s.id='jio-agent-js';s.textContent="
        + json.dumps(_AGENT_JS) + ";d.head.appendChild(s);}</script>",
        height=0, width=0)
    try:
        box, keyed = st.container(key="agent_box"), True
    except TypeError:                      # old Streamlit -> pip install -U streamlit
        box, keyed = st.expander("🤖 ISOC Assistant"), False
    with box:
        st.markdown(_HEADER, unsafe_allow_html=True)
        with (st.container(key="agent_inner") if keyed else st.container()):
            _chat_body()