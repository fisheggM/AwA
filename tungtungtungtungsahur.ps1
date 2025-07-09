#防止 远 古 Powershell 3.0 运行 该 脚本
########################################
#Requires -Version 4.0
########################################
<#
    @Editor: Notepad.EXE + Powershell ISE
    @Made by: Fails、 TNTfish、[DELETED]
    @版本状态: PRE-PRE-PRE-PRE-BETA
    @测试者:YOUYOUYOU
    @位置：https://raw.githubusercontent.com/fisheggM/AwA/refs/heads/main/tungtungtungtungsahur.ps1
    @补丁内容: Tungtungtungtung sahur
    @需要权限: 管理员级
    @保存方式：以GB10030或UTF-8编码且未受修改的方式保存（双关？)不建议使用ANSI
    @使用前的提醒：
        [01]如果您开启了纵云梯、魔法猫咪、七根棍子等可以访问XX34.XXX的工具，请关闭。
        [02]不保证成功，也不保证失败。
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
        目标代码：指作品的任何非源代码形式。2
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
    

#>

#----------------------------（不要改下面的任何内容）变名字----------------------------
$需要填充的内容 = $null
$需要填充一个正整数 = $null

#-----------------------------------可修改的配置------------------------------------------
#填写NTP网站:如(time.windows.com)，不需要加https://或http://或ws://或quic://等任何协议头
# 不能是URL Scheme（如果您不知道什么是URL Scheme可以忽略)
#不能在外宇宙网
#不能是localhost, [::1], 127.0.0.1等回环地址
# 默认值: time.windows.com
$NTP= "time.apple.com"

#好吧
#默认值：0x9
$NTPCode = "0x9"

#网络检验周期，越大越稳但结束得越慢
#默认值:10
$retries = $需要填充一个正整数

#网络检验的速度，越大越稳但执行时间上越慢
#默认值:3
$delays = $需要填充一个正整数

#保存备用文件的位置
#这个文件夹不需要保证一定存在
#但要保证有基本读写权限（遍历文件夹、创建文件、写入文件)
#默认值:"$env:TEMP/Tung4Sahur" -> ~Appdata/local/Temp/Tung4Sahur -> C:/Users/XXXXXX/Appdata/Local/temp/Tung4Sahur/
$SaveFileLoc = $需要填充的内容

#备用文件名称
#默认值:"LASTSESSION"
$SaveFileName = $需要填充的内容

#测试人员使用
$DEBUG = $False

#在PWSH中启动
$GrantInPwsh = $False


<###################################################################################################################################
---------------DANGER LINE------------------------------UNSAFE ZONE--------------------------------DANGER LINE------------------------------UNSAFE ZONE-----------------
---------------DANGER LINE------------------------------UNSAFE ZONE--------------------------------DANGER LINE------------------------------UNSAFE ZONE-----------------
---------------DANGER LINE------------------------------UNSAFE ZONE--------------------------------DANGER LINE------------------------------UNSAFE ZONE-----------------
---------------DANGER LINE------------------------------UNSAFE ZONE--------------------------------DANGER LINE------------------------------UNSAFE ZONE-----------------
---------------DANGER LINE------------------------------UNSAFE ZONE--------------------------------DANGER LINE------------------------------UNSAFE ZONE-----------------
###################################################################################################################################>


#---------------------------------默认值部分----------------------------------------------

#################################################
if (!$NTP) {$NTP = "time.windows.com"}
if(!$retries) {$retries=10}
if(!$delays) {$delays=3}
#################################################

#################################################
if(!$SaveFileLoc) {$SaveFileLoc = "$env:TEMP/Tung4Sahur"}
if(!$SaveFileName) {$SaveFileName = "LASTSESSION"}
#################################################

#################################################
if ($DEBUG) {$DebugPreference= "Continue"}
#################################################

#----------------------------------代码部分-----------------------------------------------
# 基础环境

#初始化变量
$E_FixNetFlag = $null
$Ethernet1 = $null
$Ethernet2 = $null
$Wlan = $null

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

#################################################################

function E-FixNet() {
<#
E: 实验性
作用: 修复网络
#>

#首先把干扰因素排掉
#飞机会把所有网站重定向回localhost或者一个本地网站
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

function Restart-Explorer() {Restart-Process "Explorer"}

function Set-Title ( [string] $title ) {$host.UI.RawUI.WindowTitle = $title;}

function Fuck-Proxy() {Get-Process "Clash for Windosws" -ErrorAction Ignore;if ($?) {$null = Start-Process "clash://quit";Write-Host "纵云梯已被拆除" -ForeGroundColor green};}

# Write-Host-But-Nothing
# 作用：空一行 。
function whbn() {Write-Host $null;}

#Write-Host-Echo-with-Point
# 作用：同ECHO. 。
function whep() {Write-Host $NEWLINE;}

function CleanDNS() {ipconfig /flushdns;ipconfig /registerdns;return;}

function Grant (){if($GrantInPwsh){$shell = "pwsh.EXE"}else{$shell="powershell.EXE"};if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process $shell "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs;exit}}

function Restart-Process([string]$process=$null){
    Write-Debug "IN Restart-Process"
    if (!$process) {return $False};
    $:: = Get-Process $process -ErrorAction Ignore -Verbose;
    if($? -and [boolean]$::){
        Stop-Process -InputObject $::;
        Start-Sleep -Seconds 5 -Verbose
        $:: = Get-Process $process -ErrorAction Ignore -Verbose;
        Start-Process -InputObject $::;
        return $True
    }
    Write-Debug $::
    Write-Debug "OUT Restart-Process"
}

function Write-FallbackFile() {
    Start-Transaction
    if (!(Test-path -Path $SaveFileLoc)) {mkdir $SaveFileLoc};
    if ([int]((Get-Date).year) -lt 2024 -And [int]((Get-Date).Month) -eq 1) {Undo-Transaction;Read-FallbackFile}
    Write-Debug "将时间数据写入备用文件"
    Set-Content $SaveFilePath (Get-Date)
    Write-Debug (Get-Content $SaveFilePath)
    Complete-Transaction
    Start-Transaction
    Complete-Transaction
    exit 0
}

function DangerousTSReg() {
    Write-Debug "In DangerousTSREG"
    Start-Transaction -RollbackPreference Never;

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

function Read-FallbackFile() {
    Write-Warning "启用备用计划。"
    if (!(Test-Path $SaveFilePath)) {Failed-SyncTime $False}
    $FDate = Get-Content $SaveFilePath
    Start-Transaction;
    if (
        [int]((Get-Date $FDate).year) -LT 2025 `
    -or [int]((Get-Date $FDate).Hour) -EQ 0
    ) 
    {
        Undo-Transaction;
        Failed-SyncTime $True;
    }
    Set-Date $FDate
    if (!$?) {Undo-Transaction;}
    Complete-Transaction;
    #a
    #带时间的同步
    w32tm /resync
    if (!$?) {Write-warning "无法精细地校准时间";exit -1}
    return;
}

function Failed-SyncTime([boolean]$code) {
    if (!$code) {
    Write-Warning "无法找到备份文件！直接同步时间至2025年"
    }
    else {
         Write-Warning "备份文件有误!"
    }
    Set-Date 2025/01/01
    Write-Warning "请手动微调时间!"
    Write-Warning "按下ENTER键结束程序[1/2]"
    Pause
    Write-Warning "按下ENTER键结束程序[2/2]"
    Pause
    exit -1
}

function Kill-WindowsUpdate () {
    whep;
    Write-Host "--------------------";
    Write-Host "结束";
    whbn;
    Write-Host "尝试停止Windows Update服务......."
    Write-Host "--------------------";
    whep;
    Stop-Service wuauserv
    if  ($?) {
        switch ((Get-Service wuauserv).Status) {
            $SERVICE_IS_STOPPED {
                whep;
                echo --------------------
                # 春秋笔法(?)
                Write-Host "Windows Update已被关闭" -ForegroundColor Green
                echo --------------------
                whep
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

function TimeSync() {
    CleanDNS;
    Stop-Service -name "w32time"
    Start-Transaction
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
    w32tm /config /manualpeerlist:$($NTP + "," + $NTPCode) /update /reliable:no
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





#######################################################################
function Main () {
#######################################################################
    Grant;
    CleanDNS;
    if ($DebugPreference) {Set-Date "1602/01/01";Set-StrictMode -Version latest;Set-PSDebug -Trace 0;Start-Process "Clash://";Start-Sleep -Seconds 6.66}
    Fuck-Proxy;
    Set-Title SEEWO一体机疑难杂症解决自修复实用程序;
    Kill-WindowsUpdate;
    Restart-Explorer;
#######################################################################

    TimeSync;
    # EXIT IN TimeSync
    If ($DebugPreference) {Pause}
}

main;

<###############################################################################################################################################

#所以应该不会有人真的在一体机看rxxx34吧...
#总之记得报修 这程序只是个临时解决方案

#泥门一定要买个[$9.99]键盘给[SCAM]不蓝泥们就玩不到我留在d盘的[链接已屏蔽]啦(如果你们能成哥晚成解谜的话）我留了一个金草莓??、一个[哎呀我的妈呀这是什么]、一只能爬梯子的猫、古人的智慧、windows激活器和[3.09Gib]的音乐和Windows Media Player中的一堆歌单只有知道其本质的任何生物才可以找到lololol

###############################################################################################################################################>