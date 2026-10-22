"""The one measurement of 'how big is the text of a diagram on a phone', shared by wiki_check.py --render and wiki_screens.py.

The SVG is rendered by the vendored Mermaid inside a block exactly VIEWPORT px wide (what a 390 px phone gives the diagram) and measured IN THE BROWSER:
the effective size of a label is its computed font-size multiplied by (rendered SVG width / viewBox width). The smallest text of the diagram counts (node and edge labels),
so a diagram whose edge labels are tiny fails even if its nodes are large. This is the real glyph size, not an estimate from a fixed 16 px font (state and sequence
diagrams use other font sizes and their viewBox depends on the container, which the old 16 px / viewBox-width estimate ignored).

The Mermaid theme matters: with a theme configured (initialize({theme:...}), what a real host does and what wiki_screens.py renders) labels are 16 px; without one Mermaid renders 14 px labels in a slightly
narrower layout. Both tools initialise Mermaid with INIT_JS (theme default) so they agree; `wiki_check.py --render --no-theme` re-measures the 14 px worst case."""

VIEWPORT = 390   # phone width in px
MIN_PX = 10      # hard minimum effective text size at VIEWPORT, for every diagram a page uses

# wikiMeasure(box): box already contains the rendered <svg>; returns {vw, vh, rw, scale, font, eff, who}
JS = r"""
function wikiMeasure(box){
  var svg=box.querySelector('svg'); if(!svg) return null;
  var vb=svg.viewBox&&svg.viewBox.baseVal?svg.viewBox.baseVal:{width:0,height:0};
  var rw=svg.getBoundingClientRect().width, scale=vb.width?rw/vb.width:1, min=1e9, who='';
  box.querySelectorAll('text,tspan,span,p,div').forEach(function(el){
    var own=''; for(var n=el.firstChild;n;n=n.nextSibling) if(n.nodeType===3) own+=n.nodeValue;
    if(!own.trim()) return;
    var fs=parseFloat(getComputedStyle(el).fontSize)||0; if(fs>0&&fs<min){min=fs;who=el.tagName+'.'+(el.getAttribute('class')||'')+':'+own.trim().slice(0,20);}
  });
  if(min===1e9) min=16;
  return {vw:vb.width,vh:vb.height,rw:rw,scale:scale,font:min,eff:min*scale,who:who};
}
"""


def too_small(eff, minimum=MIN_PX): return eff < minimum


def init_js(theme='default'):
    """The Mermaid initialisation both tools use (theme=None: no theme configured, the 14 px worst case)."""
    return 'mermaid.initialize({startOnLoad:false,securityLevel:"strict"' + (f',theme:"{theme}"' if theme else '') + '});'
