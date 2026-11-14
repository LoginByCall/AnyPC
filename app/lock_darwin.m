// Наблюдатели блокировки экрана (lock_darwin.go) — одной таблицей anypcLockObs. Блокировка — любое из:
//   - com.apple.screenIsLocked (NSDistributedNotificationCenter, шлёт loginwindow): ⌃⌘Q, меню Apple, заставка или сон
//     с паролем; com.apple.screensaver.didstart не слушаем — «пароль сразу» не определить (FINDINGS.md);
//   - NSWorkspaceWillSleepNotification — сон (как PrepareForSleep на Linux);
//   - NSWorkspaceSessionDidResignActiveNotification — быстрая смена пользователя: сеанс ушёл с экрана, вернуть — паролем.
// suspensionBehavior DeliverImmediately: AppKit приостанавливает распределённые уведомления приложению, ушедшему из
// активных (документация NSDistributedNotificationCenter, suspended), а AnyPC активируется окном или значком и потом
// почти всегда неактивно — с Coalesce уведомление пришло бы лишь при следующей активации (замер — FINDINGS.md).
// Проба (таблица, переданное поведение, счётчик срабатываний) — lock_probe_darwin.{go,m}, тег lockprobe. Без ARC.
#import <Cocoa/Cocoa.h>
#include "_cgo_export.h"

const struct anypcLockOb {
	int dist; // 1 — NSDistributedNotificationCenter, 0 — центр NSWorkspace
	const char *name;
} anypcLockObs[] = {
	{1, "com.apple.screenIsLocked"},
	{0, "NSWorkspaceWillSleepNotification"},
	{0, "NSWorkspaceSessionDidResignActiveNotification"},
};
const int anypcLockN = sizeof anypcLockObs / sizeof anypcLockObs[0];
long anypcLockUsed[sizeof anypcLockObs / sizeof anypcLockObs[0]] = {-1, -1, -1}; // suspensionBehavior, переданное при
                                                                                  // подписке; -1 — без него или не подписан
int anypcLockHits;                    // срабатывания наблюдателя (до Go): видно и без lockOn

@interface ALock : NSObject
@end
@implementation ALock
- (void)locked:(NSNotification *)n {
	anypcLockHits++;
	goLocked((char *)n.name.UTF8String);
}
@end

static ALock *lockObj;

void anypcLockOn(void) {
	dispatch_sync(dispatch_get_main_queue(), ^{
		if (lockObj) return;
		lockObj = [ALock new];
		NSNotificationCenter *ws = [[NSWorkspace sharedWorkspace] notificationCenter];
		for (int i = 0; i < anypcLockN; i++) {
			NSString *name = [NSString stringWithUTF8String:anypcLockObs[i].name];
			if (anypcLockObs[i].dist) {
				NSNotificationSuspensionBehavior b = NSNotificationSuspensionBehaviorDeliverImmediately;
				[[NSDistributedNotificationCenter defaultCenter] addObserver:lockObj selector:@selector(locked:) name:name
					object:nil suspensionBehavior:b];
				anypcLockUsed[i] = b;
			} else
				[ws addObserver:lockObj selector:@selector(locked:) name:name object:nil];
		}
	});
}

void anypcLockOff(void) {
	dispatch_sync(dispatch_get_main_queue(), ^{
		if (!lockObj) return;
		[[NSDistributedNotificationCenter defaultCenter] removeObserver:lockObj];
		[[[NSWorkspace sharedWorkspace] notificationCenter] removeObserver:lockObj];
		for (int i = 0; i < anypcLockN; i++) anypcLockUsed[i] = -1;
		[lockObj release];
		lockObj = nil;
	});
}
