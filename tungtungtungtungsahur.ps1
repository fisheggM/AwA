#防止 远 古 Powershell 3.0 运行 该 脚本
########################################
#Requires -Version 4.0
########################################
<#
    @Made by: Fails、 [REDACTED]、[DELETED]
    @版本状态: PRE-PRE-PRE-PRE-BETA
    @测试者:YOUYOUYOU
    @位置：https://raw.githubusercontent.com/fisheggM/AwA/refs/heads/main/tungtungtungtungsahur.ps1
    @补丁内容: Tungtungtungtung sahur
    @需要权限: 管理员级
    @保存方式：以GB18030编码且未受修改的方式保存（双关？）
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
        许可：指Fails、[REDACTED]、[DELETED]授予用户的非独占、不可转让、可撤销的许可。
        修改：一个作品是指以需要版权许可的方式对作品的全部或部分进行复制或者改编，有别于制作一致的副本。所产生的作品称为前作的修改版或基于前作的作品。
        传播：指除在计算机上执行或者修改私有副本以外，根据所适用的版权法律，只要未经许可实施就会使你承担直接或间接侵权责任的任何行为。传播包括复制、分发（无论修改与否）、向公众提供、以及在一些国家的其他行为。
        转发：指任何一种可以使其他方制作或接收该软件副本的传播行为。仅仅通过计算机网络与用户进行交互，而没有传输任何副本的行为不属于转发。
        源代码：指对作品进行修改所首选的作品形式。
        目标代码：指作品的任何非源代码形式。2
    2. 许可授予：
        2.1 Fails、[REDACTED]、[DELETED]授予您一个个人、非独占、不可转让、可撤销的许可，以使用软件，仅限于非商业目的。
        2.2 您不得出售、出租、出借、转让或以其他方式分配软件或其任何部分。
    3. 使用限制：
        3.1 您可以对软件进行反向工程、反编译或试图以任何方式发现软件的源代码，除非法律禁止，但您不可以对软件源代码做以下修改并二次分发: 加壳、加密软件源代码、未经允许的于非本地局域网中传播源代码。
        3.2 在没有经过版权许可下，该协议不可被修改。
    4. 许可费用说明：
        4.1 本软件是免费提供给用户。
    5. 责任划定：
        5.1 Fails、[REDACTED]、[DELETED] 不提供任何形式的保证，包括但不限于适销性、特定用途的适用性或不侵权的保证。
        5.2 在任何情况下，Fails、[REDACTED]、[DELETED] 对因使用或无法使用软件而引起的任何直接、间接、附带、特殊、惩罚性或后果性损害（电脑瘫痪、死机、蓝屏、内核恐慌、无法运行该程序)，均不承担责任。
    6. 许可终止：
        6.1 任何违反本协议的任何条款Fails、[REDACTED]、[DELETED] 都有权立即终止本许可。
        6.2 终止本许可后，您必须停止使用软件并销毁所有软件副本。
    7. 法律管辖与争议解决
        7.1 本协议受中国/中国香港管辖并按照该法律解释。
        7.2 任何与本协议有关的争议，Fails、[REDACTED]、[DELETED]拥有最终的解释权。
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
#网络检验周期，越大越稳但结束得越慢
#默认值:10
$retries = $需要填充一个正整数

#网络检验的速度，越大越稳但执行时间上越慢
#默认值:3
$delays = $需要填充一个正整数





#填写NTP网站:如(time.windows.com)，不需要加https://或http://或ws://或quic://等任何协议头
# 不能是URL Scheme（如果您不知道什么是URL Scheme可以忽略)
# 默认值: time.windows.com
$NTP= $需要填充的内容

#不要动
$DEBUG = $False;


#----------------------------------代码部分-----------------------------------------------
# 基础环境

# $MAX = -1
$MAX = 0xFFFFFFFF;
$NewLine = ([Environment]::NewLine);
# [删除] 为了防止Get-Service的状态显示可能含有本地化情况所以采用数字
#$ServiceIsStopped = 1
#$ServiceIsRunning = 4
# 多虑了...
# [WARN] Switch有BUG...
$ServiceIsStopped = "Stopped"
$ServiceIsRunning = "Running"

#################################################################
function Set-Title ( [string] $title ) {$host.UI.RawUI.WindowTitle = $title;}

function Fuck-Proxy() {Get-Process "Clash for Windows" -ErrorAction Ignore;if ($?) {Start-Process "clash://quit"};}

# Write-Host-But-Nothing
# 作用：空一行 。
function whbn() {Write-Host $null;}

#Write-Host-Echo-with-Point
# 作用：同ECHO. 。
function whep() {Write-Host $NewLine;}

function CleanDNS() {ipconfig /flushdns;ipconfig /registerdns;return;}

function Grant (){if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs;exit}}


function Write-FallbackFile() {
    mkdir $env:TEMP/Tung4Sahur -ErrorAction Ignore
    if ([int]((Get-Date).year) -lt 2025) {Failed-SyncTime $True}
    Set-Content $env:TEMP/Tung4Sahur/LASTSESSION (Get-Date)
    exit(0)
}

function DangerousTSReg() {
    Start-Transaction;
    $r = Get-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config\" -UseTransaction;
    if ($DEBUG) {Write-Host $r}
    $r.MaxNegPhaseCorrection = $MAX;
    $r.MaxPosPhaseCorrection = $MAX;
    Complete-Transaction;
    if ($DEBUG) {Write-Host $r}
    return;
}

function Read-FallbackFile() {
    Write-Warning "启用备用计划。"
    Get-Content $env:TEMP/Tung4Sahur/LASTSESSION
    if (!$?) {Failed-SyncTime $False;}
    $FDate = Get-Content $env:TEMP/Tung4Sahur/LASTSESSION
    Start-Transaction -RollbackPreference Never;
    Set-Date $FDateget
    if ([int]((Get-Date).year) -lt 2025) {Undo-Transaction;Failed-SyncTime $True;}
    Complete-Transaction;
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
    exit(-1)
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
            $ServiceIsStopped {
                whep;
                echo --------------------
                # 春秋笔法(?)
                Write-Host "Windows Update已被关闭" -ForegroundColor Green
                echo --------------------
                whep
            }
            $ServiceIsRunning {
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
    DangerousTSReg;
    #########################
    if (!$NTP) {$NTP = "time.windows.com"}
    if(!$retries) {$retries=10}
    if(!$delays) {$delays=3}
    #########################
    whep;
    Write-Host --------------------
    Write-Host 结束
    Write-Host 尝试联网同步时间......
    Write-Host --------------------
    whep;
    Start-Service w32time
    if  ($?) {
        switch ((Get-Service w32time).Status) {
            $ServiceIsStopped {
                whep;
                echo --------------------
                Write-Warning "Windows Time无法启动!"
                echo --------------------
                whep
            }
            $ServiceIsRunning {
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
        return
    }
    w32tm /register
    w32tm /config /manualpeerlist:$NTP /update /reliable:no
    for ($i=0; $i -lt $retries; $i++) {
        ping $NTP -n $delays
        if ($?) {w32tm /resync ;if ($?) {Write-FallbackFile} else {Read-FallbackFile}}
    }
    Write-Warning "无法同步时间！启用备用计划。"
    Read-FallbackFile;
}





#######################################################################
function Main () {
    Grant;
    Fuck-Proxy;
    Set-Title SEEWO一体机疑难杂症解决自修复实用程序;
    Kill-WindowsUpdate;
    Restart-Explorer;
    #########################################################
    TimeSync;
    # EXIT IN TimeSync
    If ($DEBUG) {Pause}
}

function Restart-Explorer() {
#  前人之述备矣
    $null
}

main;




