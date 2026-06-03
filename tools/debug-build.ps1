# 构建可调试二进制(-gcflags all=-N -l),带重试以躲过 360 对编译进程的偶发拦截。
# flaky 失败时,已成功编译的包会进缓存,反复重试会逐步收敛到成功。
# 用法(项目根目录):  powershell -ExecutionPolicy Bypass -File tools\debug-build.ps1
# 产物:app_debug.exe  ——  之后在 GoLand 用 Attach to Process 连上它调试。

$out = 'app_debug.exe'
$max = 10
for ($i = 1; $i -le $max; $i++) {
    Write-Host "[$i/$max] go build -gcflags=all=-N -l ..." -ForegroundColor Cyan
    $log = & go build -gcflags="all=-N -l" -o $out . 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "OK -> $out  (现在运行它,再用 GoLand Attach to Process 调试)" -ForegroundColor Green
        exit 0
    }
    $hiccups = ($log | Select-String 'usage: compile' | Measure-Object).Count
    if ($hiccups -gt 0) {
        Write-Host "  被 360 拦了 $hiccups 次,重试(已编译的包已进缓存)..." -ForegroundColor Yellow
    } else {
        Write-Host "  非拦截类错误:" -ForegroundColor Red
        $log | Select-Object -Last 15 | ForEach-Object { Write-Host "   $_" }
        exit 1
    }
}
Write-Host "重试 $max 次仍失败,请改用方案 A(360 信任区)" -ForegroundColor Red
exit 1
