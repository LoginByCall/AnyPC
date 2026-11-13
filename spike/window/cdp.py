import socket,os,base64,json,struct,subprocess,time,urllib.request,sys,shutil
D=os.path.dirname(os.path.abspath(__file__)); prof=D+'/chrome-profile'; shutil.rmtree(prof,ignore_errors=True)
PORT=9377
p=subprocess.Popen(['google-chrome','--user-data-dir='+prof,'--remote-debugging-address=127.0.0.1','--remote-debugging-port=%d'%PORT,'--no-first-run','--no-default-browser-check','--password-store=basic','--window-size=640,400','--app=file://'+D+'/cdp.html'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
t0=time.time()
try:
    for i in range(50):
        try: ver=json.load(urllib.request.urlopen('http://127.0.0.1:%d/json/version'%PORT,timeout=1)); break
        except Exception: time.sleep(0.2)
    print('browser',ver['Browser'])
    def ws(url):
        h=url.split('/')[2]; path='/'+url.split('/',3)[3]; s=socket.create_connection(('127.0.0.1',PORT))
        s.send(('GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n'%(path,h,base64.b64encode(os.urandom(16)).decode())).encode())
        b=b''
        while b'\r\n\r\n' not in b: b+=s.recv(4096)
        return s
    def rd(s,n):
        b=b''
        while len(b)<n: b+=s.recv(n-len(b))
        return b
    def recv(s):
        h=rd(s,2); l=h[1]&127
        if l==126: l=struct.unpack('>H',rd(s,2))[0]
        elif l==127: l=struct.unpack('>Q',rd(s,8))[0]
        return json.loads(rd(s,l))
    n=[0]
    def call(s,m,pr=None,sid=None):
        n[0]+=1; o={'id':n[0],'method':m,'params':pr or {}}
        if sid:o['sessionId']=sid
        d=json.dumps(o).encode(); mask=os.urandom(4); L=len(d)
        hd=bytes([0x81])+(bytes([0x80|L]) if L<126 else bytes([0x80|126])+struct.pack('>H',L))
        s.send(hd+mask+bytes(c^mask[i%4] for i,c in enumerate(d)))
        while True:
            r=recv(s)
            if r.get('id')==n[0]: return r.get('result',r.get('error'))
    s=ws(ver['webSocketDebuggerUrl'])
    time.sleep(1)
    tg=[t for t in call(s,'Target.getTargets')['targetInfos'] if t['type']=='page']; tid=tg[0]['targetId']
    w=call(s,'Browser.getWindowForTarget',{'targetId':tid}); wid=w['windowId']; print('1 initial',w['bounds'])
    print('2 setWindowBounds fullscreen ->',call(s,'Browser.setWindowBounds',{'windowId':wid,'bounds':{'windowState':'fullscreen'}})); time.sleep(1.5)
    print('  after',call(s,'Browser.getWindowForTarget',{'targetId':tid})['bounds'])
    print('3 back normal ->',call(s,'Browser.setWindowBounds',{'windowId':wid,'bounds':{'windowState':'normal'}})); time.sleep(1)
    print('4 move left=300,top=200,w=500,h=300 ->',call(s,'Browser.setWindowBounds',{'windowId':wid,'bounds':{'left':300,'top':200,'width':500,'height':300}})); time.sleep(1)
    print('  after',call(s,'Browser.getWindowForTarget',{'targetId':tid})['bounds'])
    sid=call(s,'Target.attachToTarget',{'targetId':tid,'flatten':True})['sessionId']
    print('5 grant windowManagement ->',call(s,'Browser.grantPermissions',{'permissions':['windowManagement']}))
    js='''(async()=>{const o={};try{const d=await window.getScreenDetails();o.screens=d.screens.map(x=>[x.label,x.left,x.top,x.width,x.height,x.isPrimary]);
      await document.documentElement.requestFullscreen({screen:d.screens[d.screens.length-1]});o.fs=!!document.fullscreenElement;
      o.kbdLock=typeof navigator.keyboard?.lock; try{await navigator.keyboard.lock();o.locked=true}catch(e){o.locked=String(e)}
      o.inner=[innerWidth,innerHeight,screenX,screenY];}catch(e){o.err=String(e)}return JSON.stringify(o)})()'''
    r=call(s,'Runtime.evaluate',{'expression':js,'awaitPromise':True,'userGesture':True,'returnByValue':True},sid); print('6 getScreenDetails+requestFullscreen({screen}) ->',r.get('result',r).get('value',r)); time.sleep(1)
    print('  window',call(s,'Browser.getWindowForTarget',{'targetId':tid})['bounds'])
    call(s,'Runtime.evaluate',{'expression':'document.exitFullscreen()','awaitPromise':True},sid)
    r=call(s,'Target.createTarget',{'url':'file://'+D+'/cdp.html','newWindow':True,'width':400,'height':300}); time.sleep(1)
    print('7 second window ->',r, call(s,'Browser.getWindowForTarget',{'targetId':r['targetId']}) if 'targetId' in r else '')
    print('elapsed %.1fs'%(time.time()-t0))
    call(s,'Browser.close')
finally:
    time.sleep(0.5); p.terminate()
    try: p.wait(5)
    except Exception: p.kill()
    shutil.rmtree(prof,ignore_errors=True)
