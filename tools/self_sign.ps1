<#
.SYNOPSIS
    生成本地测试用的自签名代码签名证书，用于验证 build_exe.py 的签名链路。

.DESCRIPTION
    仅用于**本地验证**：自签名证书不被任何其它机器信任，别人下载你的 exe
    仍会看到 SmartScreen 警告。正式发布必须用受信任 CA 签发的证书
    （见 docs/代码签名.md）。

    安全边界（刻意如此）：
      * 只操作 CurrentUser 证书存储，**永不触碰 LocalMachine**，
        因此不需要管理员权限，也不会影响同机器上的其它用户。
      * 写入「受信任的根证书颁发机构」必须显式加 -Trust。默认只创建证书、
        不修改任何信任关系——把自签根证书塞进信任库是真正的安全决定，
        不该由脚本替你默默做掉。
      * -Remove 可完整回收：删证书并解除已写入的信任。

.PARAMETER Trust
    额外把该证书加入 CurrentUser 的「受信任的根证书颁发机构」与
    「受信任的发布者」，使本机 Get-AuthenticodeSignature 显示 Valid。
    仅在这台机器上生效。

.PARAMETER Remove
    删除该 Subject 下的证书，并从信任存储中移除。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\self_sign.ps1
    创建证书并打印可用于 --cert-thumbprint 的指纹。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\self_sign.ps1 -Remove
    清理本脚本创建过的证书与信任项。
#>
[CmdletBinding()]
param(
    [string]$Subject = "CN=UniMail Dev (self-signed)",
    [string]$OutPfx = "",
    [string]$PfxPasswordEnv = "UNIMAIL_PFX_PW",
    [switch]$Trust,
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

function Get-DevCerts {
    Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $Subject }
}

if ($Remove) {
    Write-Output "=== 清理自签名证书 ==="
    $certs = @(Get-DevCerts)
    if ($certs.Count -eq 0) {
        Write-Output "  未找到 ($Subject) 的证书，无需清理"
    }
    foreach ($c in $certs) {
        foreach ($store in @("Root", "TrustedPublisher")) {
            $path = "Cert:\CurrentUser\$store"
            $hit = Get-ChildItem -Path $path -ErrorAction SilentlyContinue |
                Where-Object { $_.Thumbprint -eq $c.Thumbprint }
            if ($hit) {
                Remove-Item -Path "$path\$($c.Thumbprint)" -Force
                Write-Output "  已从 CurrentUser\$store 移除 $($c.Thumbprint)"
            }
        }
        Remove-Item -Path "Cert:\CurrentUser\My\$($c.Thumbprint)" -Force
        Write-Output "  已从 CurrentUser\My 删除 $($c.Thumbprint)"
    }
    Write-Output "  完成（未触碰 LocalMachine）"
    exit 0
}

Write-Output "=== 检查签名工具 ==="
$signtool = $null
foreach ($pattern in @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
        "$env:ProgramFiles\Windows Kits\10\bin\*\x64\signtool.exe")) {
    $found = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending
    if ($found) { $signtool = $found[0].FullName; break }
}
if ($signtool) { Write-Output "  signtool: $signtool" }
else { Write-Output "  ✗ 未找到 signtool.exe（需要 Windows SDK Signing Tools）" }

Write-Output ""
Write-Output "=== 创建自签名代码签名证书（CurrentUser\My）==="
$existing = @(Get-DevCerts)
if ($existing.Count -gt 0) {
    Write-Output "  复用已存在的证书 $($existing[0].Thumbprint)"
    $cert = $existing[0]
} else {
    $cert = New-SelfSignedCertificate `
        -Subject $Subject `
        -Type CodeSigningCert `
        -KeyUsage DigitalSignature `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddYears(3) `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3")
    Write-Output "  已创建 $($cert.Thumbprint)"
}

if ($Trust) {
    Write-Output ""
    Write-Output "=== 写入 CurrentUser 信任存储（-Trust 已显式开启）==="
    foreach ($store in @("Root", "TrustedPublisher")) {
        $already = Get-ChildItem -Path "Cert:\CurrentUser\$store" -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
        if ($already) {
            Write-Output "  CurrentUser\$store 已存在，跳过"
            continue
        }
        $storeObj = New-Object System.Security.Cryptography.X509Certificates.X509Store(
            $store, [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
        $storeObj.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $storeObj.Add($cert)
        $storeObj.Close()
        Write-Output "  已加入 CurrentUser\$store"
    }
} else {
    Write-Output ""
    Write-Output "  提示：未加 -Trust，因此本机校验会显示证书不受信任（签名本身仍然有效）。"
    Write-Output "        需要本机显示 Valid 时再加 -Trust。"
}

if ($OutPfx -ne "") {
    Write-Output ""
    Write-Output "=== 导出 PFX ==="
    $pw = [Environment]::GetEnvironmentVariable($PfxPasswordEnv)
    if ([string]::IsNullOrEmpty($pw)) {
        Write-Output "  ✗ 未设置环境变量 $PfxPasswordEnv，无法导出加密的 PFX"
        Write-Output "    （不回退到空密码：导出一个空密码的私钥文件比不导出更糟）"
    } else {
        $secure = ConvertTo-SecureString -String $pw -AsPlainText -Force
        $resolved = [System.IO.Path]::GetFullPath($OutPfx)
        $dir = Split-Path -Parent $resolved
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
        Export-PfxCertificate -Cert $cert -FilePath $resolved -Password $secure | Out-Null
        Write-Output "  已导出 $resolved"
        Write-Output "  签名命令：python build_exe.py --sign --pfx `"$resolved`" --pfx-password-env $PfxPasswordEnv"
    }
}

Write-Output ""
Write-Output "=== 下一步：签名 ==="
Write-Output "  python build_exe.py --sign --cert-thumbprint $($cert.Thumbprint) --no-timestamp"
Write-Output ""
Write-Output "  指纹：$($cert.Thumbprint)"
Write-Output "  回收：powershell -ExecutionPolicy Bypass -File tools\self_sign.ps1 -Remove"
