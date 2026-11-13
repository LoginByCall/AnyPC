#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>
// ponytail: throwaway probe, WebRTC/WebCodecs in WKWebView, offscreen, prints and exits
static NSString *JS = @"(async()=>{const r={};r.pc=typeof RTCPeerConnection;r.gum=typeof (navigator.mediaDevices&&navigator.mediaDevices.getUserMedia);\nr.vdec=typeof VideoDecoder;r.kbd=typeof (navigator.keyboard&&navigator.keyboard.lock);\ntry{r.caps=RTCRtpReceiver.getCapabilities('video').codecs.map(c=>c.mimeType).filter((v,i,a)=>a.indexOf(v)==i).join(',')}catch(e){r.caps='ERR '+e}\ntry{const a=new RTCPeerConnection(),b=new RTCPeerConnection();a.onicecandidate=e=>e.candidate&&b.addIceCandidate(e.candidate);b.onicecandidate=e=>e.candidate&&a.addIceCandidate(e.candidate);\nconst ch=a.createDataChannel('x');const got=new Promise(res=>{b.ondatachannel=e=>{e.channel.onmessage=m=>res(m.data)}});\nch.onopen=()=>ch.send('ping');await a.setLocalDescription();await b.setRemoteDescription(a.localDescription);await b.setLocalDescription();await a.setRemoteDescription(b.localDescription);\nr.dc=await Promise.race([got,new Promise(res=>setTimeout(()=>res('timeout'),5000))])}catch(e){r.dc='ERR '+e}\nfor(const c of ['vp09.00.10.08','avc1.42E01F']){try{r[c]=(await VideoDecoder.isConfigSupported({codec:c})).supported}catch(e){r[c]='ERR '+e}}\nreturn JSON.stringify(r)})()";
@interface D : NSObject <NSApplicationDelegate> @property NSWindow *w; @property WKWebView *v; @end
@implementation D
- (void)applicationDidFinishLaunching:(NSNotification *)n {
  self.w = [[NSWindow alloc] initWithContentRect:NSMakeRect(-3000,-3000,200,200) styleMask:NSWindowStyleMaskBorderless backing:NSBackingStoreBuffered defer:NO];
  self.v = [[WKWebView alloc] initWithFrame:self.w.contentView.bounds configuration:[WKWebViewConfiguration new]];
  [self.w.contentView addSubview:self.v];
  [self.v loadHTMLString:@"<html><body>p</body></html>" baseURL:[NSURL URLWithString:@"https://localhost/"]];
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1500*NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
    [self.v callAsyncJavaScript:[@"return await " stringByAppendingString:JS] arguments:@{} inFrame:nil inContentWorld:WKContentWorld.pageWorld completionHandler:^(id r, NSError *e){
      if (e) printf("JSERR %s\n", e.description.UTF8String); else printf("RESULT %s\n", [[r description] UTF8String]);
      exit(0); }]; });
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 15*NSEC_PER_SEC), dispatch_get_main_queue(), ^{ printf("TIMEOUT\n"); exit(1); });
}
@end
int main(void){ @autoreleasepool { NSApplication *a=[NSApplication sharedApplication]; D *d=[D new]; a.delegate=d; [a setActivationPolicy:NSApplicationActivationPolicyProhibited]; [a run]; } }
