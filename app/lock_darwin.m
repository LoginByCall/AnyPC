// Наблюдатели блокировки экрана (lock_darwin.go) — одной таблицей lockObs. Блокировка — любое из:
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

static const struct {
	int dist; // 1 — NSDistributedNotificationCenter (всегда DeliverImmediately), 0 — центр NSWorkspace
	const char *name;
} lockObs[] = {
	{1, "com.apple.screenIsLocked"},
	{0, "NSWorkspaceWillSleepNotification"},
	{0, "NSWorkspaceSessionDidResignActiveNotification"},
};
#define lockN (sizeof lockObs / sizeof lockObs[0])

@interface ALock : NSObject
@end
@implementation ALock
- (void)locked:(NSNotification *)n {
	goLocked((char *)n.name.UTF8String);
}
@end

static ALock *lockObj;

// Имена NSWorkspace…Notification — строки с тем же текстом (проверка — в anypcLockNames и тесте).
static NSString *lockName(int i) {
	return [NSString stringWithUTF8String:lockObs[i].name];
}

void anypcLockOn(void) {
	dispatch_sync(dispatch_get_main_queue(), ^{
		if (lockObj) return;
		lockObj = [ALock new];
		NSNotificationCenter *ws = [[NSWorkspace sharedWorkspace] notificationCenter];
		for (size_t i = 0; i < lockN; i++) {
			if (lockObs[i].dist)
				[[NSDistributedNotificationCenter defaultCenter] addObserver:lockObj selector:@selector(locked:) name:lockName(i)
					object:nil suspensionBehavior:NSNotificationSuspensionBehaviorDeliverImmediately];
			else
				[ws addObserver:lockObj selector:@selector(locked:) name:lockName(i) object:nil];
		}
	});
}

void anypcLockOff(void) {
	dispatch_sync(dispatch_get_main_queue(), ^{
		if (!lockObj) return;
		[[NSDistributedNotificationCenter defaultCenter] removeObserver:lockObj];
		[[[NSWorkspace sharedWorkspace] notificationCenter] removeObserver:lockObj];
		[lockObj release];
		lockObj = nil;
	});
}

// anypcLockNames — таблица строками «dist|ws имя immediate|-»; системные константы NSWorkspace сверены с текстом
// таблицы («≠» в строке — расхождение). Освобождает вызывающий (free).
char *anypcLockNames(void) {
	NSMutableString *s = [NSMutableString string];
	NSString *sys[] = {NSWorkspaceWillSleepNotification, NSWorkspaceSessionDidResignActiveNotification};
	size_t k = 0;
	for (size_t i = 0; i < lockN; i++) {
		[s appendFormat:@"%s %s %s", lockObs[i].dist ? "dist" : "ws", lockObs[i].name, lockObs[i].dist ? "immediate" : "-"];
		if (!lockObs[i].dist && (k >= 2 || ![sys[k++] isEqualToString:lockName(i)])) [s appendString:@" ≠"];
		[s appendString:@"\n"];
	}
	return strdup(s.UTF8String);
}

// anypcLockPostLocal — уведомление в центр NSWorkspace этого процесса (только тест: в систему не уходит).
void anypcLockPostLocal(const char *name) {
	NSString *n = [NSString stringWithUTF8String:name];
	dispatch_sync(dispatch_get_main_queue(), ^{
		[[[NSWorkspace sharedWorkspace] notificationCenter] postNotificationName:n object:nil];
	});
}

// anypcLockSuspend — приостановить распределённые уведомления этому процессу, как AppKit неактивному приложению
// (только тест: свойство процесса, в систему не уходит).
void anypcLockSuspend(int on) {
	dispatch_sync(dispatch_get_main_queue(), ^{ [NSDistributedNotificationCenter defaultCenter].suspended = on != 0; });
}
