#��ֹ Զ �� Powershell 3.0 ���� �� �ű�
########################################
#Requires -Version 4.0
########################################
<#
    @Made by: Fails�� [REDACTED]��[DELETED]
    @�汾״̬: PRE-PRE-PRE-PRE-BETA
    @������:YOUYOUYOU
    @��������: Tungtungtungtung sahur
    @��ҪȨ��: ����Ա��
    @���淽ʽ����GB18030������δ���޸ĵķ�ʽ���棨˫�أ���
    @ʹ��ǰ�����ѣ�
        [01]����������������ݡ�ħ��è�䡢�߸����ӵȿ��Է���XX34.XXX�Ĺ��ߣ���رա�
        [02]����֤�ɹ���Ҳ����֤ʧ�ܡ�
    @???:
        data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAYAAABccqhmAAAACXBIWXMAAA7EAAAOxAGVKw4bAAADm0lEQVR42u3coUoEQRjAcUcOLIJNBNNd3GTRqCgYbIYLPoNdH0K7z2C4YDMIJ1ZFMG3UJIhNuGIaH8Bg+Fhm1/n9+nB7s8efuTBfyjkvAXVatgUgAIAAAAIACAAgAIAAAAIACAAgAIAAAAIACAAgAIAAAH01sgV1SykVHQiRc07eghMAIACAAAACAAgAIACAAAACAAgAIACAAAACAAgAIACAAAC/mAcQVPo+fdTpfGvQ+2eegBMAIACAAAACAAgAIACAAAACAAgACIAtAAEABAAQAEAAAAEA/qnq5wFE76OXvk9/dfASWv/c7hZ9/tN52fdX+zwBJwAQAEAAAAEABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAgN5KOee6NyB4nzzqaP0stH58fVd0/95ODkPrbz8viz6/eQCAAAACAAgAIACAAAACAAgAIACAAAACAAgAIACAAAACAPSUeQDBeQDR+/z73w+h9fcre0X3r/TzR+cJmAcACAAgAIAAAAIACAAgAIAAAAIACAAgAIAAAAIACAAgAEBPDX4eQPQ+/8XaTujzz45XQ+vfnj78CgNm77H9P/96DK0f+jwBJwDwFwAQAEAAAAEABAAQAEAAAAEABAAQAEAAAAEABAAQAKC3qp8H8No0g/7+4+2N0PrS8whKP/+kbUPrzQMABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAAAEABAAQAKAjI1sQU/o+++XNIrR+ull2/4b+/E4AgAAAAgAIACAAgAAAAgAIACAAgAAAAgAIACAAgAAAAgB0xDyAoNL32aebCy8BJwBAAAABAAQAEABAAAABAAQAEAAQAEAAAAEABAAQAEAAgP8n5Zzr3oCUQhvw2jShz5+9r1a9/9F5BpO2Da3POScnAEAAAAEABAAQAEAAAAEABAAQAEAAAAEABAAQAEAAAAEAeqj6eQDhDax8noD7/E4AgAAAAgAIACAAgAAAAgAIACAAgAAAAgAIACAAgAAAAgB0wjyA0i+g8DyBKPf5nQAAAQAEABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAEAOiEeQBDf4HBeQJR7vM7AQACAAgAIACAAAACAAgAIACAAAACAAgAIACAAAACAAgA0AnzAMAJABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAEABAAQAAAAQAEABAAQACAv/0A1EeQhbwEqXMAAAAASUVORK5CYII=






    @ Э��:
                                                                                                                                 ��  ��  ��  ��  ��  ��  Э  ��
    1. ����:
        �����ָTungtungtungsahur.ps1 �� ������ݰ�����Э����κνű���/�������
        �û���ָ����������ʹ���ߡ��û���/�������û���
        ��ɣ�ָFails��[REDACTED]��[DELETED]�����û��ķǶ�ռ������ת�á��ɳ�������ɡ�
        �޸ģ�һ����Ʒ��ָ����Ҫ��Ȩ��ɵķ�ʽ����Ʒ��ȫ���򲿷ֽ��и��ƻ��߸ı࣬�б�������һ�µĸ���������������Ʒ��Ϊǰ�����޸İ�����ǰ������Ʒ��
        ������ָ���ڼ������ִ�л����޸�˽�и������⣬���������õİ�Ȩ���ɣ�ֻҪδ�����ʵʩ�ͻ�ʹ��е�ֱ�ӻ�����Ȩ���ε��κ���Ϊ�������������ơ��ַ��������޸���񣩡������ṩ���Լ���һЩ���ҵ�������Ϊ��
        ת����ָ�κ�һ�ֿ���ʹ��������������ո���������Ĵ�����Ϊ������ͨ��������������û����н�������û�д����κθ�������Ϊ������ת����
        Դ���룺ָ����Ʒ�����޸�����ѡ����Ʒ��ʽ��
        Ŀ����룺ָ��Ʒ���κη�Դ������ʽ��2
    2. ������裺
        2.1 Fails��[REDACTED]��[DELETED]������һ�����ˡ��Ƕ�ռ������ת�á��ɳ�������ɣ���ʹ������������ڷ���ҵĿ�ġ�
        2.2 �����ó��ۡ����⡢���衢ת�û���������ʽ������������κβ��֡�
    3. ʹ�����ƣ�
        3.1 �����Զ�������з��򹤳̡����������ͼ���κη�ʽ���������Դ���룬���Ƿ��ɽ�ֹ�����������Զ����Դ�����������޸Ĳ����ηַ�: �ӿǡ��������Դ���롢δ��������ڷǱ��ؾ������д���Դ���롣
        3.2 ��û�о�����Ȩ����£���Э�鲻�ɱ��޸ġ�
    4. ��ɷ���˵����
        4.1 �����������ṩ���û���
    5. ���λ�����
        5.1 Fails��[REDACTED]��[DELETED] ���ṩ�κ���ʽ�ı�֤�������������������ԡ��ض���;�������Ի���Ȩ�ı�֤��
        5.2 ���κ�����£�Fails��[REDACTED]��[DELETED] ����ʹ�û��޷�ʹ�������������κ�ֱ�ӡ���ӡ����������⡢�ͷ��Ի������𺦣�����̱�����������������ں˿ֻš��޷����иó���)�������е����Ρ�
    6. �����ֹ��
        6.1 �κ�Υ����Э����κ�����Fails��[REDACTED]��[DELETED] ����Ȩ������ֹ����ɡ�
        6.2 ��ֹ����ɺ�������ֹͣʹ������������������������
    7. ���ɹ�Ͻ��������
        7.1 ��Э�����й�/�й���۹�Ͻ�����ո÷��ɽ��͡�
        7.2 �κ��뱾Э���йص����飬Fails��[REDACTED]��[DELETED]ӵ�����յĽ���Ȩ��
    8. ����Э��:
        8.1 ��Э�鹹��˫�����������ɵ�ȫ��Э�飬��ȡ��������ǰ��������ͷЭ�����⡣
    9. ����
        9.1 ��Э���еı����Ϊ����ο��������ɱ�Э���һ���֡�
    10. ��������
        10.1 ��Э��û�з���ЧӦ����Ϊ����Э�顣
    

#>

#----------------------------����Ҫ��������κ����ݣ�������----------------------------
$��Ҫ�������� = $null
$��Ҫ���һ�������� = $nul

#-----------------------------------���޸ĵ�����------------------------------------------
#����������ڣ�Խ��Խ�ȵ�������Խ��
#Ĭ��ֵ:10
$retries = $��Ҫ���һ��������

#���������ٶȣ�Խ��Խ�ȵ�ִ��ʱ����Խ��
#Ĭ��ֵ:3
$delays = $��Ҫ���һ��������





#��дNTP��վ:��(time.windows.com)������Ҫ��https://��http://��ws://��quic://���κ�Э��ͷ
# ������URL Scheme���������֪��ʲô��URL Scheme���Ժ���)
# Ĭ��ֵ: time.windows.com
$NTP= $��Ҫ��������



#----------------------------------���벿��-----------------------------------------------
# ��������

# $MAX = -1
$MAX = 0xFFFFFFFF;
$DEBUG = $True;
$NewLine = ([Environment]::NewLine);
# [ɾ��] Ϊ�˷�ֹGet-Service��״̬��ʾ���ܺ��б��ػ�������Բ�������
#$ServiceIsStopped = 1
#$ServiceIsRunning = 4
# ������...
# [WARN] Switch��BUG...
$ServiceIsStopped = "Stopped"
$ServiceIsRunning = "Running"

#################################################################
function Set-Title ( [string] $title ) {$host.UI.RawUI.WindowTitle = $title;}

function Fuck-Proxy() {Get-Process "Clash for Windows" -ErrorAction Ignore;if ($?) {Start-Process "clash://quit"};}

# Write-Host-But-Nothing
# ���ã���һ�� ��
function whbn() {Write-Host $null;}

#Write-Host-Echo-with-Point
# ���ã�ͬECHO. ��
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
    Write-Warning "���ñ��üƻ���"
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
    Write-Warning "�޷��ҵ������ļ���ֱ��ͬ��ʱ����2025��"
    }
    else {
         Write-Warning "�����ļ�����!"
    }
    Set-Date 2025/01/01
    Write-Warning "���ֶ�΢��ʱ��!"
    Write-Warning "����ENTER����������[1/2]"
    Pause
    Write-Warning "����ENTER����������[2/2]"
    Pause
    exit(-1)
}

function Kill-WindowsUpdate () {
    whep;
    Write-Host "--------------------";
    Write-Host "����";
    whbn;
    Write-Host "����ֹͣWindows Update����......."
    Write-Host "--------------------";
    whep;
    Stop-Service wuauserv
    if  ($?) {
        switch ((Get-Service wuauserv).Status) {
            $ServiceIsStopped {
                whep;
                echo --------------------
                # ����ʷ�(?)
                Write-Host "Windows Update�ѱ��ر�" -ForegroundColor Green
                echo --------------------
                whep
            }
            $ServiceIsRunning {
                whep
                echo --------------------
                Pause
                Write-Warning "Windows Update�����޷��رգ�"
                echo --------------------
                whep
            }
        }
    }
    else {
        # ������˵����������
        Write-Warning " û��Ȩ�ޡ����޷���ȡ����"
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
    Write-Host ����
    Write-Host ��������ͬ��ʱ��......
    Write-Host --------------------
    whep;
    Start-Service w32time
    if  ($?) {
        switch ((Get-Service w32time).Status) {
            $ServiceIsStopped {
                whep;
                echo --------------------
                Write-Warning "Windows Time�޷�����!"
                echo --------------------
                whep
            }
            $ServiceIsRunning {
                whep
                echo --------------------
                # ����ʷ�(?)
                Write-Host "Windows Time������������" -ForegroundColor Green
                echo --------------------
                whep
            }
        }
    }
    else {
        # ������˵����������
        Write-Warning " û��Ȩ�ޡ����޷���ȡW32time����"
        # bye-bye
        return
    }
    w32tm /register
    w32tm /config /manualpeerlist:$NTP /update /reliable:no
    for ($i=0; $i -lt $retries; $i++) {
        ping $NTP -n $delays
        if ($?) {w32tm /resync ;if ($?) {Write-FallbackFile} else {Read-FallbackFile}}
    }
    Write-Warning "�޷�ͬ��ʱ�䣡���ñ��üƻ���"
    Read-FallbackFile;
}





#######################################################################
function Main () {
    Grant;
    Fuck-Proxy;
    Set-Title SEEWOһ���������֢������޸�ʵ�ó���;
    Kill-WindowsUpdate;
    Restart-Explorer;
    #########################################################
    TimeSync;
    # EXIT IN TimeSync
    If ($DEBUG) {Pause}
}

function Restart-Explorer() {
#  ǰ��֮������
    $null
}

main;




