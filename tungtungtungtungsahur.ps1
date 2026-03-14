

########### -*- Coding: UTF-8 -*-#############


<#######################################
    防止 远 古 Powershell 3.0 运行 该 脚本
    我也服了沟槽的Powershell 2.0 要 啥 啥没有.
    Powershell 2.0 没有 C# DLL 支持 我 玩个蛋.
    不 说了，我去 混沌 分裂者 总部 参军
    Site-02冲冲冲.
########################################>


########################################
#Requires -Version 4.0
########################################


<#
    @Editor: Notepad.EXE + Powershell ISE
    @Made by: Fails、 TNTfish、[DELETED]
    @版本状态: Version 2.1 Alpha
    @测试者:YOUYOUYOU
    @位置：
                 https://github.com/fisheggM/AwA/archive/refs/tags/v1.0-Beta.1.zip (初代)
                 https://raw.githubusercontent.com/fisheggM/AwA/refs/heads/Branch_v2.1-Alpha/tungtungtungtungsahur.ps1 (当前版本)
 	 https://raw.githubusercontent.com/fisheggM/AwA/refs/heads/main/tungtungtungtungsahur.ps1 (最新[未实装]版本）
                 https://raw.githubusercontent.com/fisheggM/AwA/refs/heads/CoolerUpdate/tungtungtungtungsahur.ps1 （ [v2.0] 较稳定的版本）
                 https://raw.githubusercontent.com/fisheggM/AwA/refs/heads/RetroTUI/Celeste.ps1 (一点也不酷炫的TUI界面) （画饼中)
                 
    @补丁内容: 产品完善性更新.
    @需要权限: 管理员级.
    @保存方式：以GB10030或UTF-8编码且未受修改的方式保存, 不建议使用ANSI
    @使用前的提醒：
        [01]如果您开启了纵云梯、魔法猫咪、七根棍子等可以访问XX34.XXX的工具，请关闭。
        [02]不保证成功，也不保证失败。
        [03]不要在00:00-01:00期间运行该脚本.
    @???:
    data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAYAAABccqhmAAAACXBIWXMAAA7EAAAOxAGVKw4bAAADm0lEQVR42u3coUoEQRjAcUcOLIJNBNNd3GTRqCgYbIYLPoNdH0K7z2C4YDMIJ1ZFMG3UJIhNuGIaH8Bg+Fhm1/n9+nB7s8efuTBfyjkvAXVatgUgAIAAAAIACAAgAIAAAAIACAAgAIAAAAIACAAgAIAAAH01sgV1SykVHQiRc07eghMAIACAAAACAAgAIACAAAACAAgAIACAAAACAAgAIACAAAC/mAcQVPo+fdTpfGvQ+2eegBMAIACAAAACAAgAIACAAAACAAgACIAtAAEABAAQAEAAAAEA/qnq5wFE76OXvk9/dfASWv/c7hZ9/tN52fdX+zwBJwAQAEAAAAEABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAgN5KOee6NyB4nzzqaP0stH58fVd0/95ODkPrbz8viz6/eQCAAAACAAgAIACAAAACAAgAIACAAAACAAgAIACAAAACAPSUeQDBeQDR+/z73w+h9fcre0X3r/TzR+cJmAcACAAgAIAAAAIACAAgAIAAAAIACAAgAIAAAAIACAAgAEBPDX4eQPQ+/8XaTujzz45XQ+vfnj78CgNm77H9P/96DK0f+jwBJwDwFwAQAEAAAAEABAAQAEAAAAEABAAQAEAAAAEABAAQAKC3qp8H8No0g/7+4+2N0PrS8whKP/+kbUPrzQMABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAAAEABAAQAKAjI1sQU/o+++XNIrR+ull2/4b+/E4AgAAAAgAIACAAgAAAAgAIACAAgAAAAgAIACAAgAAAAgB0xDyAoNL32aebCy8BJwBAAAABAAQAEABAAAABAAQAEAAQAEAAAAEABAAQAEAAgP8n5Zzr3oCUQhvw2jShz5+9r1a9/9F5BpO2Da3POScnAEAAAAEABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAAAEAeqj6eQDhDax8noD7/E4AgAAAAgAIACAAgAAAAgAIACAAgAAAAgAIACAAgAAAAgB0wjyA0i+g8DyBKPf5nQAAAQAEABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAEAOiEeQBDf4HBeQJR7vM7AQACAAgAIACAAAACAAgAIACAAAACAAgAIACAAAACAAgA0AnzAMAJABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAEABAAQACAv/0A1EeQhbwEqXMAAAAASUVORK5CYII=






    @ 协议:
                                                                                                                                 最  终  用  户  许  可  协  议
    1. 定义:
        软件：指Tungtungtungsahur.ps1 或 软件内容包含此协议的任何脚本和/或软件。
        用户：指您或该软件的使用者、用户和/或最终用户。
        许可：指Fails、TNTfish、[DELETED]授予用户的非独占、不可转让、可撤销的许可。
        修改：一个作品是指以需要版权许可的方式对作品的全部或部分进行复制或者改编，有别于制作一致的副本。所产生的作品称为前作的修改版或基于前作的作品。
        传播：指除在计算机上执行或者修改私有副本以外，根据所适用的版权法律，只要未经许可实施就会使你承担直接或间接侵权责任的任何行为。传播包括复制、分发（无论修改与否）、向公众提供、以及在一些国家的其他行为。
        转发：指任何一种可以使其他方制作或接收该软件副本的传播行为。仅仅通过计算机网络与用户进行交互，而没有传输任何副本的行为不属于转发。
        源代码：指对作品进行修改所首选的作品形式。
        目标代码：指作品的任何非源代码形式。
    2. 许可授予：
        2.1 Fails、TNTfish、[DELETED]授予您一个个人、非独占、不可转让、可撤销的许可，以使用软件，仅限于非商业目的。
        2.2 您不得出售、出租、出借、转让或以其他方式分配软件或其任何部分。
    3. 使用限制：
        3.1 您可以对软件进行反向工程、反编译或试图以任何方式发现软件的源代码，除非法律禁止，但您不可以对软件源代码做以下修改并二次分发: 加壳、加密软件源代码、未经允许的于非本地局域网中传播源代码。
        3.2 在没有经过版权许可下，该协议不可被修改。
    4. 许可费用说明：
        4.1 本软件是免费提供给用户。
    5. 责任划定：
        5.1 Fails、TNTfish、[DELETED] 不提供任何形式的保证，包括但不限于适销性、特定用途的适用性或不侵权的保证。
        5.2 在任何情况下，Fails、TNTfish、[DELETED] 对因使用或无法使用软件而引起的任何直接、间接、附带、特殊、惩罚性或后果性损害（电脑瘫痪、死机、蓝屏、内核恐慌、无法运行该程序)，均不承担责任。
    6. 许可终止：
        6.1 任何违反本协议的任何条款Fails、TNTfish、[DELETED] 都有权立即终止本许可。
        6.2 终止本许可后，您必须停止使用软件并销毁所有软件副本。
    7. 法律管辖与争议解决
        7.1 本协议受中国/中国香港管辖并按照该法律解释。
        7.2 任何与本协议有关的争议，Fails、TNTfish、[DELETED]拥有最终的解释权。
    8. 完整协议:
        8.1 本协议构成双方关于软件许可的全部协议，并取代所有先前的书面或口头协议和理解。
    9. 其他
        9.1 本协议中的标题仅为方便参考，不构成本协议的一部分。
    10. 修正内容
        10.1 本协议没有法律效应，仅为君子协议。
        10.2 [DELETED]不指代任何人，仅为保留选项，无表示意义.
        10.3 如果你在遵守该协议的同时对该脚本做出了有意义的代码修改，您可以将你的网名附在@Make by:后

#>

#-------------------神秘开关--------------------

################################################
# 在PWSH中启动
# 默认值：$False
$GrantInPwsh = $False

# 测试人员使用
# 不是哥们测试人员就我一个有必要写一个神人$DEBUG吗
$DEBUG = $True
#################################################


#------------------------------------------------


#------------------神秘处理----------------------

#################################################
if ($DEBUG) {$DebugPreference= "Continue"}
if ($DebugPreference) {Set-Date "1601/01/01";Set-StrictMode -Version latest;Set-PSDebug -Trace 2;}
#################################################

#------------------------------------------------



#----------------------------（不要改下面的任何内容）变名字-------------------------------

$需要填充的内容 = $null
$需要填充一个正整数 = $null

#-----------------------------------------------------------------------------------------


<#--------------------------------------更改须知------------------------------------------#

$需要填充的内容这一栏必须要括上单引号或双引号
单/双引号不能是中文全角单/双引号，必须是英文半角双引号
中文全角：”“ ’ ‘
英文半角：" " ' '

例如：
$SaveFileName = "随便填写一些内容阿萨的会计分录奥萨蒂哦飞机阿斯顿四奥迪放假啊阿斯蒂芬哦i啊撒旦解放撒P"
$SaveFileName = '随便填写一些内容ask的房价肯定很舒服萨弗鲁阿斯顿法律上的回复楼上的发哈绿豆沙v巴哈ULB'


#-----------------------------------可修改的配置------------------------------------------#>

# 填写NTP网站:如(time.windows.com)，不需要加https://或http://或ws://或quic://等任何协议头
# 不能是URL Scheme（如果您不知道什么是URL Scheme可以忽略)
# 不能在外宇宙网
# 不能是localhost, [::1], 127.0.0.1等回环地址
# 不能是保留地址
# 默认值: "time.windows.com"
# 建议设定值: "time.apple.com"

$NTP= "time.apple.com"

# 好吧
# 我也不知道这玩意拿来干什么的.
# 勿动
#默认值："0x9"
$NTPCode = "0x9"

# 网络检验周期，越大越稳但结束得越慢
# 默认值:10
$retries = $需要填充一个正整数

# 网络检验的速度，越大越稳但执行时间上越慢
# 默认值:3
$delays = $需要填充一个正整数

# 保存备用文件的位置
# 这个文件夹不需要保证一定存在
# 但要保证其上级目录有基本读写权限（如遍历文件夹、创建文件、读取文件、写入文件等)
# 默认值:"$env:TEMP/Tung4Sahur" -> ~Appdata/local/Temp/Tung4Sahur -> C:/Users/XXXXXX/Appdata/Local/temp/Tung4Sahur/
$SaveFileLoc = $需要填充的内容

# 备用文件名称
# 默认值:"LASTSESSION"
$SaveFileName = $需要填充的内容

# 信任时间数据文件位置
# 这个文件夹不需要保证一定存在
# 但要保证有其上级目录基本读写权限（如遍历文件夹、创建文件、读取文件、写入文件等)
# 默认值: $SaveFileLoc ( 的值 )
$TrustedFileLoc = $需要填充的内容

# 信任时间数据文件名称
# 默认值:"TRUSTEDFILE"
$TrustedFileName = $需要填充的内容

# 失败后回滚的日期
# 失败后回滚日期与今天实际日期的日期差不能超过50天
# 不然就会触发NET::ERR_CERT_DATE_INVALID（时钟过慢）
# 也不能超过今天实际日期，会触发net::ERR_CERT_DATE_INVALID（时钟过快）
# 不需要填写hms（小时、分钟、秒数及以后）
# ISO格式：yyyy/mm/dd
# 默认值：暂无
$FailedFallbackDate = "2025/09/01"




#-----------------------------------------------------------------------------------------------------------------------------------------------

<###################################################################################################################################
---------------DANGER LINE------------------------------UNSAFE ZONE--------------------------------DANGER LINE------------------------------UNSAFE ZONE-----------------
---------------DANGER LINE------------------------------UNSAFE ZONE--------------------------------DANGER LINE------------------------------UNSAFE ZONE-----------------
---------------DANGER LINE------------------------------UNSAFE ZONE--------------------------------DANGER LINE------------------------------UNSAFE ZONE-----------------
---------------DANGER LINE------------------------------UNSAFE ZONE--------------------------------DANGER LINE------------------------------UNSAFE ZONE-----------------
---------------DANGER LINE------------------------------UNSAFE ZONE--------------------------------DANGER LINE------------------------------UNSAFE ZONE-----------------
###################################################################################################################################>


#---------------------------------默认值部分----------------------------------------------

# _: [ref]$foo "如果$foo是$NULL或1/N个空格则设定为这个字符串参数"
#                   如果$foo不是$NULL则保持不变
function _:{[OutputType()]param([parameter(Mandatory=$true)][ref]$data,[parameter(Mandatory=$true)]$v)process{if([System.String]::IsNullOrWhiteSpace($data.Value)){$data.Value=$v;Write-Debug "`$data -> $($data.Value)"};Write-Debug "$data stays to config val."}}


#################################################
_: ([ref]$NTP) "time.windows.com"
_: ([ref]$delays) 3
#################################################

#################################################
_: ([ref]$SaveFileLoc) "$env:TEMP/Tung4Sahur"
_: ([ref]$SaveFileName) "LASTSESSION"
#################################################


#################################################
_: ([ref]$TrustedFileLoc) $SaveFileLoc
_: ([ref]$TrustedFileName) "TRUSTEDFILE"
#################################################


#----------------------------------代码部分-----------------------------------------------
# 基础环境

# C# Tweak
$Member =
'
[DllImport("user32.dll")] public static extern bool EnableMenuItem(long hMenuItem, long uIDItem, long uFlag);
[DllImport("user32.dll")] public static extern long GetSystemMenu(IntPtr hMenuHandle, bool bReset);
[DllImport("user32.dll")] public static extern long SetWindowsLongPtr(long hMenuHandle, long nIndex, long dwNewLong);
[DllImport("user32.dll")] public static extern bool EnableWindow(long hMenuHandle, int FlagEnable);
[DllImport("user32.dll")] public static extern bool RegisterHotKey(IntPtr hWnd, int id, long fsModifiers, long vk);
[DllImport("user32.dll")] public static extern bool UnregisterHotKey(IntPtr hWnd, int id, long fsModifiers, long vk);
[DllImport("user32.dll")] public static extern bool DrawMenuBar(IntPtr hWnd);
'

#所有的ENUM都不支持函数热加载...
#函数仍保持着ENUM修改前的参数限制...

# http://msdn.microsoft.com/zh-cn/library/windows/desktop/ms646360(v=vs.85).aspx
ENUM MENUITEM {
    SC_CLOSE= 0xF060;
    SC_CONTEXTHELP= 0xF180;
    SC_DEFAULT= 0xF160; # 双击窗口
    SC_MAXIMIZE= 0XF030;
    SC_MINIMIZE= 0XF020;
}

# http://msdn.microsoft.com/zh-cn/library/windows/desktop/ms647636(v=vs.85).aspx
ENUM ENABLEFLAGS {
    MF_BYCOMMAND= 0X00000000L;
    MF_BYPOSITION= 0X00000400L;
    MF_DISABLED= 0X00000002L;
    MF_ENABLED= 0X00000000L;
    MF_GRAYED= 0X00000001L;
}

# https://learn.microsoft.com/zh-cn/windows/win32/api/winuser/nf-winuser-registerhotkey#parameters
ENUM FSMODIFERS {
    ALT= 0x0001;
    CTRL= 0x0002;
    NOREPEAT= 0x4000;
    SHIFT= 0x0004;
    SUPER= 0x0008
}

# https://learn.microsoft.com/zh-cn/windows/desktop/inputdev/virtual-key-codes
ENUM VK {
    F4= 0x73;
    Y= 0x59;
    N= 0x4E;
    NULL= 0x00
}


#初始化变量
$E_FixNetFlag = $null
$Ethernet1 = $null
$Ethernet2 = $null
$Wlan = $null
$proceed = $null

$MAX = 0xFFFFFFFF;

$NEWLINE = ([Environment]::NewLine);

# [删除] 为了防止Get-Service的状态显示可能含有本地化情况所以采用数字
#$SERVICE_IS_STOPPED = 1
#$SERVICE_IS_RUNNING = 4
# 多虑了...
# [FIX] [WARN] Switch有BUG...
$SERVICE_IS_STOPPED = "Stopped"
$SERVICE_IS_RUNNING = "Running"

$SaveFilePath = (Join-Path $SaveFileLoc $SaveFileName)

$TrustedFilePath = (Join-Path $TrustedFileLoc $TrustedFileName)

#################################################################

# Write-Host-But-Nothing
# 作用：空一行 。
function whbn {[OutputType()]param()process{Write-Host $null;}}

#Write-Host-Echo-with-Point
# 作用：同ECHO. 。
function whep {[OutputType()]param()process{Write-Host $NEWLINE;}}

#包装 restart-process
function Restart-Explorer {[OutputType()]param()process{Restart-Process "Explorer"}}

function Null-Key(){[OutputType()]param()process {$null = $host.UI.RawUI.ReadKey()}} # PowerShell ISE 不支持 ReadKey(); 

function CleanDNS {[OutputType()]param()process{ipconfig /flushdns;ipconfig /registerdns;return;}}

#同CMD TITLE
function Set-Title {[OutputType()]param([Parameter(Mandatory=$true)][string]$title)process{$host.UI.RawUI.WindowTitle = $title;}}

#作用: 加载c#代码
function Load {[OutputType([System.Boolean])]param()process{Add-Type -MemberDefinition:$Member -Name:User32 -Namespace:External;return $?}}

#作用：替代Pause
function Do-Pause {[OutputType()]param([Parameter(Mandatory=$true)][System.String]$Text)process{Write-Host $Text -NoNewline;;}}

#作用：去除CLXXH(通过clXXh scheme: clXXh://quit)
function Fuck-Proxy {[OutputType()]param()process{Get-Process "Clash for Windows" -ErrorAction Ignore;if($?){$null = Start-Process "clash://quit";Write-Host "纵云梯已被拆除" -ForeGroundColor green};}}

#作用：合法UAC提权
function Grant{[OutputType()]param()process{if($GrantInPwsh){$shell="pwsh.EXE"}else{$shell="powershell.EXE"};if(-NOT([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")){Start-Process $shell "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs;exit}}}

#比Do-Pause更好
#不需要按回车键
#但会显示用户按键...
#适用于Y/N决策

function Wait-Key() {
    [OutputType([System.Boolean])]
    param (
        [parameter(Mandatory=$True)]
        [VK[]]$Keys
    )
    process {
        if ($Keys.value__.Contains($host.UI.RawUI.ReadKey().VirtualKeyCode)) {return $keys.value__} else {Return $False}
    }
}

function Write-FallbackFile {
    [OutputType()]
    param(
        
    )
    process {
        Start-Transaction -Independent
        if (!(Test-path -Path $SaveFileLoc)) {mkdir $SaveFileLoc};
        else {Write-Warning "$SaveFileLoc 在管理员权限下不可达";Undo-Transaction;Pau}
        if ([int]((Get-Date).year) -lt 2024 -And [int]((Get-Date).Month) -eq 1) {Undo-Transaction;Read-FallbackFile}
        Write-Host "将时间数据写入备用文件"
        Set-Content $SaveFilePath ([DateTime]::Now.ToFileTime().ToString())
        Write-Host (Get-Content $SaveFilePath)
        Complete-Transaction
        Do-Pause "按回车键退出[0/1]"
        exit 0
    }
}

function DangerousTSReg {
    [OutputType([System.Boolean])]
    param(
            
    )
    process {
        Write-Debug "In DangerousTSREG"
        Start-Transaction -RollbackPreference Never -Independent
        $:: = Get-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config\" -UseTransaction;
        Write-Debug $::
        if ($::.MaxNegPhaseCorrection -eq $MAX){Undo-Transaction;return $True}
        Set-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config\" -Name "MaxNegPhaseCorrection" -Value $MAX -Type "Dword" -Verbose;
        if(!$?){Undo-Transaction;return $False};
        if ($::.MaxPosPhaseCorrection -eq $MAX) {Undo-Transaction;return $True}
        Set-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config\" -Name "MaxPosPhaseCorrection" -Value $MAX -Type "Dword" -Verbose;
        if(!$?){Undo-Transaction;return $False};
        Complete-Transaction;
        $:: = Get-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config\";
        Write-Debug $::
        return $True;
    }
}

function Deltarune {
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param (
        [Parameter(Mandatory=$true)]
        [DateTime]$SyncedTime,

        [Parameter(Mandatory=$true)]
        [DateTime]$FallbackTime
    )
    process {
    # [out] @[hashtable]{Stat:ErrPos | Pos | Neg ->  2 | 0 | 1, TimeDelta: [TimeSpan] ($SyncedTime - $FallbackTime)}
    # [do] 用来计算w32tm校准后与备用文件的时间差
        $TimeDelta = $SyncedTime - $FallbackTime
        switch ($SyncedTime.CompareTo($FallbackTime)) {
            ($_ -ge 1*365*24*3600) {
                return @{Stat=2;TimeDelta=$TimeDelta}
            }
            ($_ -ge 0) {
                return @{Stat=0;TimeDelta=$TimeDelta}
            }
            ($_ -lt 0) {
                # 感觉这里应该不会执行
                return @{Stat=1;TimeDelta=$TimeDelta}
            }
        }
    }
}


function Restart-Process {
    param(
        [Parameter(Mandatory=$true)]
        [string]$process=$null
    )
    process {
        Write-Debug "IN Restart-Process"
        $:: = Get-Process $process -ErrorAction Ignore -Verbose;
        if($? -and [boolean]$::){
            Stop-Process -InputObject $::;
            Start-Sleep -Seconds 5 -Verbose
            $:: = Get-Process $process -ErrorAction Ignore -Verbose;
            Start-Process -InputObject $::;
            Write-Debug $::
            Write-Debug "OUT Restart-Process"
            return $True
        }
        return $False
    }
}

function E-FixNet {
<#
E: 实验性
作用: 修复网络
#>
    [OutputType([System.Boolean])]
    param(
        
    )
    process {
        #首先把干扰因素排掉.
        #飞机可能会绑一个虚拟网卡从而干扰寻找.
        Fuck-Proxy;

        #找出有线连接
        #由于本地化因素网络适配器没有统一的名字或代号
        #这里也只能看厂家给网络适配器设置了什么名字.
        #一般来说都是以太网和WIFI(WLAN)
        #WLAN(WIFI)应该没有中文的本地化.
        #找到就重启
        #找不到会是$null
        $Ethernet1 = [boolean](Get-NetAdapter -Name "以太网*" -Physical | Restart-NetAdapter)
        Write-Debug (Get-NetAdapter -Name "以太网*" -Physical)
        $Ethernet2 = [boolean](Get-NetAdapter -Name "Ethernet*" -Physical | Restart-NetAdapter)
        Write-Debug (Get-NetAdapter -Name "Ethernet*" -Physical)
        $Wlan = [boolean](Get-NetAdapter -Name "W*" -Physical | Restart-NetAdapter)
        Write-Debug (Get-NetAdapter -Name "W*" -Physical)

        #很原始的故障判定
        if ($Ethernet1 -or $Ethernet2 -or $Wlan){return $False} else {return $True}
    }
}

function Read-FallbackFile {
    [OutputType()]
    param(
        
    )
    process {
        Write-Warning "启用备用计划。"
        if (!(Test-Path $SaveFilePath)) {Failed-SyncTime $False}
        $FTick = Get-Content $SaveFilePath
        $FDate = [System.DateTime]::FromFileTime($FTick)
        Start-Transaction -Independent
        # 我猜没有人会在00:00开机
        if ([int]($FDate.Hour) -lt 1)  {
            Undo-Transaction;
            Failed-SyncTime $True;
        }
        Set-Date $FDate
        if (!$?) {Undo-Transaction;}
        Complete-Transaction;
        Start-Transaction -Independent
        #带时间的同步
        w32tm /resync
        if (!$?) {Write-warning "无法精细地校准时间";exit -1}
        $:: = Deltarune (Get-Date) (Get-Date $FDate)
        switch ($::) {
            0 {
                Complete-Transaction
                Write-Host "备用时间比同步后时间偏差了+$($::.TimeDelta.TotalSeconds.ToString())秒" -ForegroundColor Cyan
                Write-FallbackFile
            }
            1 {
                Undo-Transaction
                Write-Host "备用时间比同步后时间偏差了$($::.TimeDelta.TotalSeconds.ToString())秒" -ForegroundColor Cyan
                Write-Host "w32tm同步无效，时间数据将不会写入备用文件中" -ForegroundColor Red
                exit 1
            }
            2 {
                Undo-Transaction
                Write-Host "备用时间比同步后时间相差超过1年?!相差$($::.TimeDelta.TotalSeconds.ToString())" -ForegroundColor Red
                Write-Host "w32tm同步无效，时间数据将回滚至备用文件"
                Set-Date $FDate
                
            }
        }
        return;
    }
}

function Failed-SyncTime {
    [OutPutType()]
    param (
        [Parameter(Mandatory=$true)]
        [System.Boolean]$code
    )
    process {
        if (!$code) {
        Write-Warning "无法找到备份文件！直接同步时间至 $FailedFallbackDate"
        }
        else {
             Write-Warning "备份文件有误! 直接同步时间至 $FailedFallbackDate"
        }
        Set-Date $FailedFallbackDate
        Write-Warning "请手动微调时间!"
        Set-TrustedTime;

    }
}

function Set-TrustedTime {
    [OutputType()]

    param(

    )

    begin {
        Start-Process -Verb Runas "$env:windir\System32\timedate.cpl"
        $wshell = New-Object -ComObject wscript.shell
        $wshell.AppActivate((Get-Process rundll32)[0].Id)
        Start-Sleep -Seconds 0.01
        $wshell.SendKeys("D")

        whep;
        Write-Host "--------------------";
        whbn;
        Write-Host "请在弹出的时间设置窗口中设定好现实时间(精确到分)"
        whbn;
        Write-Host "--------------------";
        Write-Warning "设定结束后直接关闭时间设置窗口，当前的时间将会记录到硬盘作为同步失败后最后的回滚"
        Write-Warning "请不要关闭该窗口."
        Write-Host "等待用户关闭操作..."
        Wait-Process "rundll32"
    }

    process {
        $TrustedDate = [System.Datetime]::now
        if (!(Test-path -Path $TrustedFileLoc)) {mkdir $TrustedFileLoc};
        else {Write-Host "$TrustedFileLoc 在管理员权限下不可达";exit -1}
        Start-Transaction -Independent
        Set-Content -Value $TrustedDate.ToFileTime() -Path $TrustedFilePath
        if ($?) {
            Write-Warning "是否将信任时间设置为$NEWLINE$([datetime]::Now.ToLocalTime().ToString("yyyy年 M月 d日 dddd tt hh:mm:ss UTCz"))?$NEWLINE[Y/N](按下Y键或N键， Y（es）键继续，N（o）键重来)"
            $proceed = Wait-Key Y,N
            if ($proceed) {
                Complete-Transaction
                Write-Debug (Get-Content -Path $TrustedFilePath)
                Write-Host "时间数据成功写入!"
                Do-Pause("按回车键退出[0/1]")
                exit 0
            }
            else {Do-Pause "按回车键重来...";Undo-Transaction;Set-TrustedTime} # 递归循环
        }
    }
}

function Kill-WindowsUpdate {
    [OutputType()]
    param(
        
    )
    begin {
        whep;
        Write-Host "--------------------";
        Write-Host "结束";
        whbn;
        Write-Host "尝试停止Windows Update服务......."
        Write-Host "--------------------";
        whep;
    }
    process {
        Stop-Service wuauserv
        if  ($?) {
            switch ((Get-Service wuauserv).Status) {
                $SERVICE_IS_STOPPED {
                    whep;
                    echo --------------------
                    # 春秋笔法(?)
                    Write-Host "Windows Update已被关闭" -ForegroundColor Cyan
                    echo --------------------
                    whep
	    Set-Service -Name "wuauserv" -StartupType Disabled;
    }
    end {
	    if ($?) {
	        whep;
                        echo --------------------
                        # 春秋笔法(?)
                        Write-Host "Windows Update已被禁用" -ForegroundColor Green
                        echo --------------------
                        whep
	    }
                }
                $SERVICE_IS_RUNNING {
                    whep
                    echo --------------------
                    Pause
                    Write-Warning "Windows Update服务无法关闭！"
                    echo --------------------
                    whep
                }
            }
        }
        else {
            # 正常来说到不了这里
            Write-Warning " 没有权限、或无法读取服务"
        }
    }
}

function TimeSync {
    [OutputType()]
    param(
        
    )
    process {
        CleanDNS;
        Stop-Service -name "w32time"
        Start-Transaction -Independent
        w32tm /unregister
        Stop-Service -name "w32time" -ErrorAction SilentlyContinue;
        Start-Sleep -Seconds 6.66
    <#
        [BUG]在"w32time服务已运行"的情况下执行w32tm /unregister会有幽灵服务的BUG; 
    #>
        w32tm /register
        [boolean]$:: = DangerousTSReg;
        Write-Debug "exit DangerousTSReg"
        if (!$::){Write-Warning "无法修改注册表!"}
        whep;
        Write-Host --------------------
        Write-Host 结束
        Write-Host 尝试联网同步时间......
        Write-Host --------------------
        whep;
        Start-Service w32time
        if  ($?) {
            switch ((Get-Service w32time).Status) {
                $SERVICE_IS_STOPPED {
                    whep;
                    echo --------------------
                    Write-Warning "Windows Time无法启动!"
                    echo --------------------
                    whep
                }
                $SERVICE_IS_RUNNING {
                    whep
                    echo --------------------
                    # 春秋笔法(?)
                    Write-Host "Windows Time服务已启动。" -ForegroundColor Green
                    echo --------------------
                    whep
                }
            }
        }
        else {
            # 正常来说到不了这里
            Write-Warning " 没有权限、或无法读取W32time服务。"
            # bye-bye
            exit -1
        }
        w32tm /config /manualpeerlist:"$NTP,$NTPCode" /update /reliable:no
        for ($i=0; $i -lt $retries; $i++) {
            ping $NTP -n $delays
            if ($?) {w32tm /resync ;if ($?) {Write-FallbackFile}}
        }
        if (!$E_FixNetFlag) {
            E-FixNet;
            $E_FixNetFlag = $True;
            TimeSync
        }
        else {
            Write-Warning "尝试修复网络......但效果并不显著";
        }
        Write-Warning "无法同步时间！启用备用计划。"
        Read-FallbackFile;
    }
}

function Fuck-Quit {
    [OutputType()]
    param (
        
    )
    begin {
        Write-Host  "Fuck Quit --- 防熊孩子装置"
        whep;
        if (Load) {
            Write-Host "成功引入外部C#函数!"
            whep;
            Write-Host "----------------------"
            Write-Host "禁用窗体关闭功能..."
            Write-Host "----------------------"
            whep;
            Write-Warning "如果 您 *真的* 想要关闭该窗口，键入 Ctrl+C 或 在任务栏 鼠标右键 该窗口图标 -> 选择 关闭窗口 / 关闭所有窗口 "
        } 
        else {Write-Warning "引入外部C#函数失败,防熊孩子装置将失效!(这并不是您的问题)";return $False;}
    }
    process {
        Write-Host "寻找该窗口."
        $PSProcess = Get-Process -Pid $PID
        Write-Debug $PSProcess
        Write-Host "寻找主窗口句柄."
        $handle = $PSProcess.MainWindowHandle
        Write-Debug $handle
        Write-Host "获取控制菜单."
        $m = [External.user32]::GetSystemMenu($handle, 0);
        Write-Debug $m
        Write-Host "禁用关闭功能."
        $Stat = [External.user32]::EnableMenuItem($m,  [MENUITEM]::SC_CLOSE.value__, [ENABLEFLAGS]::MF_GRAYED.value__);
        if ($? -and $Stat -ne -1) {Write-Host "关闭功能已禁用."}
        else {Write-Warning "未能成功禁用!";return $False}
    }
    end {
        Write-Host "强制刷新菜单栏"
        [External.user32]::DrawMenuBar($handle);
        pause;
    }
}

#######################################################################
function Main () {
    [OutputType()]
    param(
        
    )
    process {

#######################################################################
        Grant;
        Set-Title SEEWO一体机疑难杂症解决自修复实用程序;
        Fuck-Quit;
        CleanDNS;
        Fuck-Proxy;
        Kill-WindowsUpdate;
        Restart-Explorer;
#######################################################################

        TimeSync;
        # EXIT IN TimeSync
        If ($DebugPreference) {Pause}
    }
}

Main;


<###############################################################################################################################################

 所以应该不会有人真的在一体机看rxxx34吧...
 总之记得报修 这程序只是个临时解决方案

###############################################################################################################################################>