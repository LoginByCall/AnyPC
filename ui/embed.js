// Вкладка «Мои ПК»: страница открыта во фрейме и берёт привязки Go у окна-родителя
// (то же окно AnyPC или браузера). Подключается ДО основного скрипта: APP и привязки должны
// быть на месте, когда он выполняется. Внешний файл того же источника — CSP ('self') не трогаем.
// На Windows WebView2 кладёт свои заглушки привязок и в дочерний фрейм, но ответ Go уходит в
// верхний документ — во фрейме вызов зависнет. Поэтому берём привязки у родителя БЕЗУСЛОВНО
// (перекрываем заглушки фрейма); на unix/в браузере это те же рабочие функции.
if (window.parent !== window) try {
  const p = window.parent;
  for (const n of ['hostInfo', 'pakeRespond', 'hostVerify', 'clientSign', 'knownGet', 'knownSet',
    'ckeyGet', 'ckeySet', 'savedGet', 'savedSet', 'setPassword', 'setConfirm', 'setViewOnly', 'setNode',
    'otpNew', 'otpEnable', 'otpOff', 'newCode', 'userSet', 'userDel', 'keyDel', 'hostDisconnect',
    'quit', 'minimize', 'fullscreen', 'openUpdate', 'openSite', 'getClip', 'setClip',
    'fileOpen', 'fileWrite', 'fileFinish', 'fileAbort', 'audioAnswer', 'audioMic', 'uiGet', 'uiSet'])
    if (typeof p[n] === 'function') window[n] = p[n];
  if (p.ANYPC) window.ANYPC = p.ANYPC;
} catch {}
