#define variable
$change_or_notChange_time = Read-Host -Prompt "(Đổi giờ = y; `r`n Trở về giờ hiện tại = n ?)  (y/n) `r`n"

#begin run
$change_or_notChange_time
if ($change_or_notChange_time -eq "y")
	{
    $date = Read-Host -Prompt "NHẬP ngày giờ muốn đổi (VD: 31/03/2020 10:16:00) `r`n"
	set-service -name w32time -startuptype 'disabled'
	stop-service -name w32time 
	set-date -date "$date"	
	Write-Host -Object "Đã đổi giờ THÀNH CÔNG" -ForegroundColor Green
	Write-Host -NoNewline -Object "Nhập phím bất kỳ.....để thoát" -ForegroundColor Yellow
		Read-Host
		break
	}
elseif ($change_or_notChange_time -eq "n")
	{
	set-service -name w32time -startuptype 'automatic'
	start-service -name w32time 
	Write-Host "Đã trở về ngày giờ hiện tại !" -ForegroundColor Green
	Write-Host -NoNewline -Object "Nhập phím bất kỳ.....để thoát" -ForegroundColor Yellow
		Read-Host
		break
	}
else 
	{
	Write-Host -Object "Giờ vẫn như cũ, CHƯA THAY ĐỔI" -ForegroundColor Red
	Write-Host -NoNewline -Object "Nhập phím bất kỳ.....để thoát" -ForegroundColor Yellow
		Read-Host
		break
	}