// Системная авторизация настроек AnyPC: стандартное окно LocalAuthentication.
#import <LocalAuthentication/LocalAuthentication.h>

int anypcAuthorize(void) {
	LAContext *ctx = [LAContext new];
	dispatch_semaphore_t done = dispatch_semaphore_create(0);
	__block BOOL ok = NO;
	[ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
	   localizedReason:@"Подтвердите изменение настроек AnyPC системной учётной записью."
	             reply:^(BOOL success, NSError *error) {
		ok = success;
		dispatch_semaphore_signal(done);
	}];
	dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
	[ctx release];
	return ok ? 0 : 1;
}
