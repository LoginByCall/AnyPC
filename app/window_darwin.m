// Своё окно AnyPC на Маке (UI-REDESIGN, решение 4, маршрут M1): NSWindow + WKWebView со страницей ui/index.html как есть
// (привязки — локальный HTTP API с токеном, main_unix.go), значок в строке меню (NSStatusItem). Всё AppKit — на главном
// потоке: его держит main() (window_darwin.go), вызовы из Go уходят туда через dispatch. Без ARC (cgo CFLAGS общие с C).
#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>
#include "_cgo_export.h"

// Родное поверх привязок страницы: полный экран — окна (отдельный Space), сайт — в браузере по умолчанию (адреса в Go).
// До страницы и только в главном фрейме: свойства неизменяемы, присваивание прокладки (main_unix.go, shimmed) мимо;
// фреймы «Мои ПК» берут эти функции у родителя (ui/embed.js), сообщение уходит из главного фрейма.
static NSString *const nativeJS = @"(() => { const p = (...a) => webkit.messageHandlers.anypc.postMessage(a);"
	"for (const [k, f] of Object.entries({fullscreen: on => p('fs', !!on), openUpdate: () => p('update'), openSite: () => p('site')}))"
	" Object.defineProperty(window, k, {value: f, writable: false}); })();";
// Полный экран снят системой (зелёная кнопка, ⌃⌘F): странице и её фреймам «Мои ПК» — как после долгого Esc.
static NSString *const fsExitJS = @"try { window.embedFsExit && embedFsExit(); document.querySelectorAll('iframe').forEach(f => "
	"{ try { f.contentWindow.embedFsExit && f.contentWindow.embedFsExit(); } catch (e) {} }); } catch (e) {}";

static void activate(void) { // macOS 14: activateIgnoringOtherApps не действует, activate — с согласия активного приложения
	if (@available(macOS 14, *)) [NSApp activate];
	else [NSApp activateIgnoringOtherApps:YES];
}
static NSString *str(const char *s) { return s ? [NSString stringWithUTF8String:s] : @""; }
static BOOL ru(void) { return [[NSLocale preferredLanguages].firstObject hasPrefix:@"ru"]; }
static void openExternal(NSURL *u) {
	if ([u.scheme isEqual:@"https"] || [u.scheme isEqual:@"http"]) [[NSWorkspace sharedWorkspace] openURL:u];
}

@interface AWin : NSObject <WKScriptMessageHandler, WKUIDelegate, WKNavigationDelegate, WKDownloadDelegate, NSWindowDelegate>
@property(assign) int wid;
@property(retain) NSWindow *win;
@property(retain) WKWebView *web;
@property(retain) NSURL *own; // адрес своего сервера (http://127.0.0.1:порт): только туда окну можно
@end

static NSMutableDictionary *wins; // номер → AWin
static int nextWin = 1, mainWin;

@implementation AWin
- (void)dealloc {
	[_win release];
	[_web release];
	[_own release];
	[super dealloc];
}
- (BOOL)ownURL:(NSURL *)u { return [u.scheme isEqual:@"http"] && [u.host isEqual:self.own.host] && [u.port isEqual:self.own.port]; }
- (BOOL)ownOrigin:(WKSecurityOrigin *)o { return [o.protocol isEqual:@"http"] && [o.host isEqual:self.own.host] && o.port == self.own.port.integerValue; }
- (void)userContentController:(WKUserContentController *)c didReceiveScriptMessage:(WKScriptMessage *)m {
	NSArray *a = [m.body isKindOfClass:[NSArray class]] ? m.body : nil;
	if (!a.count || !m.frameInfo.isMainFrame || ![self ownOrigin:m.frameInfo.securityOrigin]) return;
	if ([a[0] isEqual:@"fs"]) {
		BOOL on = a.count > 1 && [a[1] boolValue], is = (self.win.styleMask & NSWindowStyleMaskFullScreen) != 0;
		if (on != is) [self.win toggleFullScreen:nil];
	} else if ([a[0] isEqual:@"update"]) goOpenSite(0);
	else if ([a[0] isEqual:@"site"]) goOpenSite(1);
}
- (void)windowDidExitFullScreen:(NSNotification *)n { [self.web evaluateJavaScript:fsExitJS completionHandler:nil]; }
// не вышло (экран заблокирован, приложение не активно) — страница не должна думать, что она во весь экран
- (void)windowDidFailToEnterFullScreen:(NSWindow *)w { [self.web evaluateJavaScript:fsExitJS completionHandler:nil]; }
- (void)windowWillClose:(NSNotification *)n {
	if (self.win.attachedSheet) [self.win endSheet:self.win.attachedSheet]; // alert/confirm/выбор файла — ответ «нет»
	[self.web.configuration.userContentController removeScriptMessageHandlerForName:@"anypc"]; // иначе цикл ссылок
	[self.web loadHTMLString:@"" baseURL:nil]; // уйти со страницы: сессия WebRTC закрывается
	if (mainWin == self.wid) mainWin = 0;
	int wid = self.wid;
	dispatch_async(dispatch_get_main_queue(), ^{ [wins removeObjectForKey:@(wid)]; });
}
// alert/confirm (удаление записи, отзыв ключа) и выбор файла: без них WKWebView молча отвечает «нет»
- (void)webView:(WKWebView *)w runJavaScriptAlertPanelWithMessage:(NSString *)msg initiatedByFrame:(WKFrameInfo *)f completionHandler:(void (^)(void))done {
	NSAlert *a = [[NSAlert new] autorelease];
	a.messageText = msg;
	[a beginSheetModalForWindow:self.win completionHandler:^(NSModalResponse r) { done(); }];
}
- (void)webView:(WKWebView *)w runJavaScriptConfirmPanelWithMessage:(NSString *)msg initiatedByFrame:(WKFrameInfo *)f completionHandler:(void (^)(BOOL))done {
	NSAlert *a = [[NSAlert new] autorelease];
	a.messageText = msg;
	[a addButtonWithTitle:@"OK"];
	[a addButtonWithTitle:ru() ? @"Отмена" : @"Cancel"];
	[a beginSheetModalForWindow:self.win completionHandler:^(NSModalResponse r) { done(r == NSAlertFirstButtonReturn); }];
}
- (void)webView:(WKWebView *)w runOpenPanelWithParameters:(WKOpenPanelParameters *)p initiatedByFrame:(WKFrameInfo *)f completionHandler:(void (^)(NSArray<NSURL *> *))done {
	NSOpenPanel *o = [NSOpenPanel openPanel];
	o.allowsMultipleSelection = p.allowsMultipleSelection;
	[o beginSheetModalForWindow:self.win completionHandler:^(NSModalResponse r) { done(r == NSModalResponseOK ? o.URLs : nil); }];
}
- (WKWebView *)webView:(WKWebView *)w createWebViewWithConfiguration:(WKWebViewConfiguration *)c forNavigationAction:(WKNavigationAction *)a windowFeatures:(WKWindowFeatures *)f {
	openExternal(a.request.URL); // target=_blank — в браузер по умолчанию
	return nil;
}
// Окно ходит только по своей странице; чужой адрес — в браузер по умолчанию (щелчок по ссылке) или мимо.
- (void)webView:(WKWebView *)w decidePolicyForNavigationAction:(WKNavigationAction *)a decisionHandler:(void (^)(WKNavigationActionPolicy))done {
	NSURL *u = a.request.URL;
	if (a.shouldPerformDownload) done(WKNavigationActionPolicyDownload);
	else if ([self ownURL:u] || [u.absoluteString isEqual:@"about:blank"] || [u.scheme isEqual:@"blob"]) done(WKNavigationActionPolicyAllow);
	else {
		if (a.navigationType == WKNavigationTypeLinkActivated) openExternal(u);
		done(WKNavigationActionPolicyCancel);
	}
}
// Микрофон — только своей странице (сам getUserMedia появится лишь с NSMicrophoneUsageDescription, FINDINGS.md)
- (void)webView:(WKWebView *)w requestMediaCapturePermissionForOrigin:(WKSecurityOrigin *)o initiatedByFrame:(WKFrameInfo *)f type:(WKMediaCaptureType)t decisionHandler:(void (^)(WKPermissionDecision))done {
	done([self ownOrigin:o] && t == WKMediaCaptureTypeMicrophone ? WKPermissionDecisionGrant : WKPermissionDecisionDeny);
}
- (void)webView:(WKWebView *)w decidePolicyForNavigationResponse:(WKNavigationResponse *)r decisionHandler:(void (^)(WKNavigationResponsePolicy))done {
	done(r.canShowMIMEType ? WKNavigationResponsePolicyAllow : WKNavigationResponsePolicyDownload);
}
- (void)webView:(WKWebView *)w navigationAction:(WKNavigationAction *)a didBecomeDownload:(WKDownload *)d { d.delegate = self; }
- (void)webView:(WKWebView *)w navigationResponse:(WKNavigationResponse *)r didBecomeDownload:(WKDownload *)d { d.delegate = self; }
// a.download (выгрузка статистики CSV) — в «Загрузки», имя не затирает существующий файл
- (void)download:(WKDownload *)d decideDestinationUsingResponse:(NSURLResponse *)r suggestedFilename:(NSString *)name completionHandler:(void (^)(NSURL *))done {
	NSFileManager *fm = [NSFileManager defaultManager];
	NSURL *dir = [fm URLsForDirectory:NSDownloadsDirectory inDomains:NSUserDomainMask].firstObject;
	NSString *base = name.lastPathComponent.length ? name.lastPathComponent : @"download", *ext = base.pathExtension;
	NSURL *u = [dir URLByAppendingPathComponent:base];
	for (int i = 1; [fm fileExistsAtPath:u.path] && i < 1000; i++) {
		NSString *n = [NSString stringWithFormat:@"%@ (%d)", base.stringByDeletingPathExtension, i];
		u = [dir URLByAppendingPathComponent:ext.length ? [n stringByAppendingPathExtension:ext] : n];
	}
	done(u);
}
@end

// openOnMain — окно со страницей u на мониторе monitor (индекс NSScreen; < 0 — экран с фокусом); main — главное окно
// AnyPC: одно, повторный вызов поднимает его. seed — скрипт до страницы (localStorage окна ПК). 0 — не создано.
static int openOnMain(NSString *u, NSString *title, int monitor, int main, NSString *seed) {
	AWin *old = mainWin ? wins[@(mainWin)] : nil;
	if (main && old) {
		activate();
		[old.win makeKeyAndOrderFront:nil];
		return mainWin;
	}
	NSArray *ss = [NSScreen screens];
	NSScreen *sc = monitor < 0 ? ([NSScreen mainScreen] ?: ss.firstObject) : (monitor < (int)ss.count ? ss[monitor] : nil);
	NSURL *url = [NSURL URLWithString:u];
	if (!sc || !url.host || !url.port) return 0;
	NSRect vf = sc.visibleFrame, r = vf;
	if (main) {
		r.size = NSMakeSize(MIN(1100, vf.size.width), MIN(720, vf.size.height));
		r.origin = NSMakePoint(NSMidX(vf) - r.size.width / 2, NSMidY(vf) - r.size.height / 2);
	}
	AWin *w = [[AWin new] autorelease];
	WKWebViewConfiguration *c = [[WKWebViewConfiguration new] autorelease];
	c.mediaTypesRequiringUserActionForPlayback = WKAudiovisualMediaTypeNone; // звук удалённого ПК без щелчка
	if (!main) c.websiteDataStore = [WKWebsiteDataStore nonPersistentDataStore]; // окно ПК: seed не затирает хранилище главного
	[c.userContentController addScriptMessageHandler:w name:@"anypc"];
	if (seed.length)
		[c.userContentController addUserScript:[[[WKUserScript alloc] initWithSource:seed injectionTime:WKUserScriptInjectionTimeAtDocumentStart forMainFrameOnly:YES] autorelease]];
	[c.userContentController addUserScript:[[[WKUserScript alloc] initWithSource:nativeJS injectionTime:WKUserScriptInjectionTimeAtDocumentStart forMainFrameOnly:YES] autorelease]];
	NSWindowStyleMask st = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable;
	w.win = [[[NSWindow alloc] initWithContentRect:r styleMask:st backing:NSBackingStoreBuffered defer:NO] autorelease];
	if (!main) [w.win setFrame:vf display:NO];
	w.win.releasedWhenClosed = NO;
	w.win.title = title;
	w.win.delegate = w;
	w.win.collectionBehavior = NSWindowCollectionBehaviorFullScreenPrimary;
	w.web = [[[WKWebView alloc] initWithFrame:w.win.contentView.bounds configuration:c] autorelease];
	w.web.UIDelegate = w;
	w.web.navigationDelegate = w;
	w.win.contentView = w.web;
	w.own = [NSURL URLWithString:@"/" relativeToURL:url].absoluteURL;
	w.wid = nextWin++;
	wins[@(w.wid)] = w;
	if (main) mainWin = w.wid;
	[w.web loadRequest:[NSURLRequest requestWithURL:url]];
	activate();
	[w.win makeKeyAndOrderFront:nil];
	return w.wid;
}

int anypcGUI(void) { // есть графический сеанс (не ssh, не служба вне Aqua): иначе NSApplication не к кому подключиться
	CFDictionaryRef d = CGSessionCopyCurrentDictionary();
	if (d) CFRelease(d);
	return d != NULL;
}

// Выход через AppKit (выход из сеанса, перезагрузка) — как «Выйти»: Go снимает пропуска и завершает процесс сам.
@interface AApp : NSObject <NSApplicationDelegate>
@end
@implementation AApp
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)a {
	goQuit();
	return NSTerminateLater; // ответа не будет: процесс выйдет из Go (Cancel сорвал бы выход из сеанса)
}
@end

void anypcRun(void) {
	@autoreleasepool {
		wins = [NSMutableDictionary new];
		[NSApplication sharedApplication];
		[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory]; // без значка в Dock: вход — строка меню
		NSApp.delegate = [AApp new];
		// ⌘C/⌘V/⌘A в полях страницы идут через меню «Правка»; полосы меню у такого приложения нет, сочетания работают
		NSMenu *bar = [[NSMenu new] autorelease], *edit = [[[NSMenu alloc] initWithTitle:@"Edit"] autorelease];
		NSMenuItem *ei = [[NSMenuItem new] autorelease];
		ei.submenu = edit;
		[bar addItem:ei];
		struct { NSString *t; SEL s; NSString *k; } e[] = {{@"Undo", @selector(undo:), @"z"}, {@"Redo", @selector(redo:), @"Z"},
			{@"Cut", @selector(cut:), @"x"}, {@"Copy", @selector(copy:), @"c"}, {@"Paste", @selector(paste:), @"v"}, {@"Select All", @selector(selectAll:), @"a"}};
		for (size_t i = 0; i < sizeof e / sizeof e[0]; i++) [edit addItemWithTitle:e[i].t action:e[i].s keyEquivalent:e[i].k];
		NSMenu *win = [[[NSMenu alloc] initWithTitle:@"Window"] autorelease]; // ⌘W — закрыть, ⌃⌘F — полный экран
		NSMenuItem *wi = [[NSMenuItem new] autorelease];
		wi.submenu = win;
		[bar addItem:wi];
		[win addItemWithTitle:@"Close" action:@selector(performClose:) keyEquivalent:@"w"];
		[[win addItemWithTitle:@"Full Screen" action:@selector(toggleFullScreen:) keyEquivalent:@"f"] setKeyEquivalentModifierMask:NSEventModifierFlagControl | NSEventModifierFlagCommand];
		NSApp.mainMenu = bar;
		[NSApp run];
	}
}

int anypcOpen(const char *url, const char *title, int monitor, int main, const char *seed) {
	__block int id = 0;
	@autoreleasepool {
		NSString *u = str(url), *t = str(title), *s = str(seed);
		dispatch_sync(dispatch_get_main_queue(), ^{ id = openOnMain(u, t, monitor, main, s); });
	}
	return id;
}

// anypcEval — тело async-функции в окне wid; ответ — goEvalDone(seq, ok, строка).
void anypcEval(int wid, const char *body, int seq) {
	@autoreleasepool {
		NSString *b = str(body);
		dispatch_async(dispatch_get_main_queue(), ^{
			AWin *w = wins[@(wid)];
			if (!w) {
				goEvalDone(seq, -1, (char *)"окно закрыто");
				return;
			}
			[w.web callAsyncJavaScript:b arguments:@{} inFrame:nil inContentWorld:WKContentWorld.pageWorld completionHandler:^(id r, NSError *e) {
				if (e) goEvalDone(seq, 0, (char *)e.localizedDescription.UTF8String);
				else goEvalDone(seq, 1, (char *)([r isKindOfClass:[NSString class]] ? [r UTF8String] : ""));
			}];
		});
	}
}

void anypcClose(int wid) {
	dispatch_async(dispatch_get_main_queue(), ^{ [[wins[@(wid)] win] close]; });
}

// anypcScreens — мониторы JSON-массивом в порядке NSScreen.screens (0 — с полосой меню); координаты — точки,
// начало — левый верхний угол основного, как у getScreenDetails. Освобождает вызывающий (free).
char *anypcScreens(void) {
	__block char *res = NULL;
	dispatch_sync(dispatch_get_main_queue(), ^{
		@autoreleasepool {
			NSArray *ss = [NSScreen screens];
			CGFloat h = ss.count ? [ss[0] frame].size.height : 0;
			NSMutableArray *a = [NSMutableArray array];
			for (NSUInteger i = 0; i < ss.count; i++) {
				NSScreen *s = ss[i];
				NSRect f = s.frame;
				[a addObject:@{@"label" : s.localizedName ?: @"", @"left" : @(f.origin.x), @"top" : @(h - f.origin.y - f.size.height),
					@"width" : @(f.size.width), @"height" : @(f.size.height), @"primary" : @((BOOL)(i == 0)), @"scale" : @(s.backingScaleFactor)}];
			}
			NSData *d = [NSJSONSerialization dataWithJSONObject:a options:0 error:nil];
			res = strndup(d.bytes, d.length);
		}
	});
	return res;
}

@interface ATray : NSObject
@end
@implementation ATray
- (void)click:(NSMenuItem *)i { goTrayClick((int)i.tag); }
@end

static NSStatusItem *tray;
static ATray *trayTarget;

// anypcTray — значок в строке меню: «имя · ID» (1) и «Помочь кому-то…» (2) — окно, «Выйти» (4), как в трее Linux.
void anypcTray(const char *title, const char *help, const char *quit) {
	@autoreleasepool {
		NSArray *items = @[ str(title), str(help), @"", str(quit) ];
		dispatch_async(dispatch_get_main_queue(), ^{
			if (tray) return;
			tray = [[[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength] retain];
			NSImage *img = [NSImage imageWithSystemSymbolName:@"display" accessibilityDescription:@"AnyPC"];
			if (img) {
				img.template = YES;
				tray.button.image = img;
			} else
				tray.button.title = @"AnyPC";
			tray.button.toolTip = items[0];
			if (!trayTarget) trayTarget = [ATray new];
			NSMenu *m = [[NSMenu new] autorelease];
			for (NSUInteger i = 0; i < items.count; i++) {
				if (![items[i] length]) {
					[m addItem:[NSMenuItem separatorItem]];
					continue;
				}
				NSMenuItem *it = [m addItemWithTitle:items[i] action:@selector(click:) keyEquivalent:@""];
				it.target = trayTarget;
				it.tag = i + 1;
			}
			tray.menu = m;
		});
	}
}

void anypcTrayOff(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		if (tray) [[NSStatusBar systemStatusBar] removeStatusItem:tray];
		[tray release];
		tray = nil;
	});
}
