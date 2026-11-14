//go:build lockprobe

// Проба детектора блокировки (lock_probe_darwin.go): только сборка с тегом lockprobe, в программу не входит.
#import <Cocoa/Cocoa.h>

struct anypcLockOb {
	int dist;
	const char *name;
};
extern const struct anypcLockOb anypcLockObs[];
extern const int anypcLockN;
extern long anypcLockUsed[];
extern int anypcLockHits;

// anypcLockProbeNames — таблица строками «dist|ws имя поведение» (поведение — переданное при подписке:
// immediate | coalesce | hold | drop | -); имена NSWorkspace сверены с системными константами («≠» — расхождение).
char *anypcLockProbeNames(void) {
	__block NSMutableString *s;
	dispatch_sync(dispatch_get_main_queue(), ^{
		s = [[NSMutableString alloc] init];
		NSString *sys[] = {NSWorkspaceWillSleepNotification, NSWorkspaceSessionDidResignActiveNotification};
		int k = 0;
		for (int i = 0; i < anypcLockN; i++) {
			const char *b = "-";
			switch (anypcLockUsed[i]) {
			case NSNotificationSuspensionBehaviorDeliverImmediately: b = "immediate"; break;
			case NSNotificationSuspensionBehaviorCoalesce: b = "coalesce"; break;
			case NSNotificationSuspensionBehaviorHold: b = "hold"; break;
			case NSNotificationSuspensionBehaviorDrop: b = "drop"; break;
			}
			[s appendFormat:@"%s %s %s", anypcLockObs[i].dist ? "dist" : "ws", anypcLockObs[i].name, b];
			if (!anypcLockObs[i].dist && (k >= 2 || ![sys[k++] isEqualToString:@(anypcLockObs[i].name)])) [s appendString:@" ≠"];
			[s appendString:@"\n"];
		}
	});
	char *r = strdup(s.UTF8String);
	[s release];
	return r;
}

// anypcLockProbeHits — срабатывания наблюдателя (на главном потоке, где он и считает).
int anypcLockProbeHits(void) {
	__block int n;
	dispatch_sync(dispatch_get_main_queue(), ^{ n = anypcLockHits; });
	return n;
}

// anypcLockProbePost — уведомление в центр NSWorkspace этого процесса (в систему не уходит).
void anypcLockProbePost(const char *name) {
	NSString *n = @(name);
	dispatch_sync(dispatch_get_main_queue(), ^{
		[[[NSWorkspace sharedWorkspace] notificationCenter] postNotificationName:n object:nil];
	});
}

// anypcLockProbeSuspend — приостановить распределённые уведомления этому процессу, как AppKit неактивному приложению
// (свойство процесса, в систему не уходит).
void anypcLockProbeSuspend(int on) {
	dispatch_sync(dispatch_get_main_queue(), ^{ [NSDistributedNotificationCenter defaultCenter].suspended = on != 0; });
}
