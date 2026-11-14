// Наблюдатели блокировки экрана (lock_darwin.go). Блокировка — любое из:
//   - com.apple.screenIsLocked (NSDistributedNotificationCenter, шлёт loginwindow): ⌃⌘Q, меню Apple, заставка или сон
//     с паролем; com.apple.screensaver.didstart не слушаем — «пароль сразу» не определить (FINDINGS.md);
//   - NSWorkspaceWillSleepNotification — сон (как PrepareForSleep на Linux);
//   - NSWorkspaceSessionDidResignActiveNotification — быстрая смена пользователя: сеанс ушёл с экрана, вернуть — паролем.
// suspensionBehavior DeliverImmediately: AppKit приостанавливает распределённые уведомления приложению, ушедшему из
// активных (документация NSDistributedNotificationCenter, suspended), а AnyPC активируется окном или значком и потом
// почти всегда неактивно — с Coalesce уведомление пришло бы лишь при следующей активации. Ни разу не активированному
// процессу доходит и с Coalesce (замер на Маке, FINDINGS.md). Без ARC (как window_darwin.m).
#import <Cocoa/Cocoa.h>
#include "_cgo_export.h"

@interface ALock : NSObject
@end
@implementation ALock
- (void)locked:(NSNotification *)n {
	goLocked((char *)n.name.UTF8String);
}
@end

static ALock *lockObs;

void anypcLockOn(void) {
	dispatch_sync(dispatch_get_main_queue(), ^{
		if (lockObs) return;
		lockObs = [ALock new];
		[[NSDistributedNotificationCenter defaultCenter] addObserver:lockObs selector:@selector(locked:)
			name:@"com.apple.screenIsLocked" object:nil suspensionBehavior:NSNotificationSuspensionBehaviorDeliverImmediately];
		NSNotificationCenter *ws = [[NSWorkspace sharedWorkspace] notificationCenter];
		[ws addObserver:lockObs selector:@selector(locked:) name:NSWorkspaceWillSleepNotification object:nil];
		[ws addObserver:lockObs selector:@selector(locked:) name:NSWorkspaceSessionDidResignActiveNotification object:nil];
	});
}

void anypcLockOff(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		if (!lockObs) return;
		[[NSDistributedNotificationCenter defaultCenter] removeObserver:lockObs];
		[[[NSWorkspace sharedWorkspace] notificationCenter] removeObserver:lockObs];
		[lockObs release];
		lockObs = nil;
	});
}
