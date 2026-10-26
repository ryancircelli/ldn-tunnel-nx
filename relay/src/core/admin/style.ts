export const STYLE = `
:root{color-scheme:light dark;--bg:#fff;--fg:#111;--mut:#666;--line:#8884;--acc:#0a5;--bad:#c22}
@media (prefers-color-scheme:dark){:root{--bg:#16181c;--fg:#eee;--mut:#aaa;--acc:#3c8;--bad:#f66}}
body{font:16px/1.5 system-ui,sans-serif;max-width:46rem;margin:0 auto;padding:1rem;color:var(--fg);background:var(--bg)}
h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:1.8rem}
.card,.row{border:1px solid var(--line);border-radius:.5rem;padding:.7rem;margin:.6rem 0}
.head{display:flex;align-items:center;gap:.5rem}.name{flex:1;min-width:0;font:inherit;padding:.3rem;border:1px solid transparent;background:transparent;color:inherit;border-radius:.3rem}
.name:hover,.name:focus{border-color:var(--line)}
.dot{width:.8rem;height:.8rem;border-radius:50%;flex:none}.on{background:var(--acc)}.off{background:#8888}
.meta,.muted{color:var(--mut);font-size:.9rem}.warn,.err{color:var(--bad)}.acts{margin-top:.4rem}
button,input[type=password],input[type=text]{font:inherit;padding:.45rem .8rem;border-radius:.3rem;border:1px solid var(--line);background:transparent;color:inherit}
button{cursor:pointer}button.danger{color:var(--bad)}button:disabled{opacity:.5}
pre,code{font-family:ui-monospace,monospace;font-size:.8rem}pre{white-space:pre-wrap;word-break:break-all;max-height:20rem;overflow:auto;margin:.4rem 0 0}
code.link,.cmd{display:block;word-break:break-all;padding:.5rem;border:1px solid var(--line);border-radius:.3rem;margin:.4rem 0}
[hidden]{display:none!important}
`;
