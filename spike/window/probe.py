import sys, gi
gi.require_version('Gtk','3.0'); gi.require_version('WebKit2','4.1')
from gi.repository import Gtk, WebKit2, GLib, Gdk
webrtc = sys.argv[1]=='1'; full = len(sys.argv)>2 and sys.argv[2]=='full'
w=Gtk.Window(title='anypc-webkit-probe'); w.set_default_size(700,300)
s=WebKit2.Settings(); s.set_property('enable-webrtc',webrtc); s.set_property('enable-media-stream',True)
s.set_property('media-playback-requires-user-gesture',False)
v=WebKit2.WebView(); v.set_settings(s); w.add(v)
print('backend',type(Gdk.Display.get_default()).__name__,'enable-webrtc',webrtc,flush=True)
v.connect('notify::title',lambda *a: print('TITLE',v.get_title(),flush=True) or ('DONE' in (v.get_title() or '') and not full and GLib.timeout_add(300,Gtk.main_quit)))
v.connect('permission-request',lambda v,r: r.allow() or True)
v.load_uri('file://'+sys.argv[0].rsplit('/',1)[0]+'/probe.html')
w.show_all()
if full:
    d=Gdk.Display.get_default(); n=d.get_n_monitors()
    for i in range(n):
        m=d.get_monitor(i); g=m.get_geometry(); print('monitor',i,m.get_model(),g.x,g.y,g.width,g.height,'primary',m.is_primary(),flush=True)
    tgt=n-1
    def go():
        w.fullscreen_on_monitor(d.get_default_screen(),tgt); return False
    def rep():
        win=w.get_window(); m=d.get_monitor_at_window(win); idx=[i for i in range(n) if d.get_monitor(i)==m]
        print('fullscreen target',tgt,'actual monitor',idx,'size',w.get_size(),'state',win.get_state(),flush=True); return False
    GLib.timeout_add(1500,go); GLib.timeout_add(3500,rep); GLib.timeout_add(4500,Gtk.main_quit)
GLib.timeout_add(18000,Gtk.main_quit)
Gtk.main()
