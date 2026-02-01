#Requires -Version 3.0

# Configurar um host Windows para gerenciamento remoto com Ansible
# -----------------------------------------------------------
#
# Este script verifica a configuração atual do WinRM (PS Remoting) e faz
# as alterações necessárias para permitir que o Ansible se conecte, autentique e
# execute comandos do PowerShell.
#
# IMPORTANTE: Este script usa certificados autoassinados e mecanismos de autenticação
# que se destinam apenas a ambientes de desenvolvimento e fins de avaliação.
# Ambientes de produção e implantações que são expostas na rede devem
# usar certificados assinados por CA e mecanismos de autenticação seguros, como o Kerberos.
#
# Para executar este script no Powershell:
#
# [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# $url = "https://raw.githubusercontent.com/ansible/ansible-documentation/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
# $file = "$env:temp\ConfigureRemotingForAnsible.ps1"
#
# (New-Object -TypeName System.Net.WebClient).DownloadFile($url, $file)
#
# powershell.exe -ExecutionPolicy ByPass -File $file
#
# Todos os eventos são registrados no Log de Eventos do Windows, útil para execuções não assistidas.
#
# Use a opção -Verbose para ver as mensagens de saída detalhadas.
#
# Use a opção -CertValidityDays para especificar por quanto tempo este certificado é válido
# a partir de hoje. Então, você especificaria -CertValidityDays 3650 para obter
# um certificado válido por 10 anos.
#
# Use a opção -ForceNewSSLCert se o sistema foi SysPreped e um novo
# Certificado SSL deve ser forçado no Listener do WinRM ao executar este
# script novamente. Isso é necessário quando um novo SID e nome CN são criados.
#
# Use a opção -EnableCredSSP para habilitar o CredSSP como uma opção de autenticação.
#
# Use a opção -DisableBasicAuth para desabilitar a autenticação básica.
#
# Use a opção -SkipNetworkProfileCheck para ignorar a verificação do perfil de rede.
# Sem especificar isso, o script será executado apenas se as interfaces do dispositivo
# estiverem nas zonas DOMAIN ou PRIVATE. Forneça esta opção se você quiser habilitar
# o WinRM em um dispositivo com uma interface na zona PUBLIC.
#
# Use a opção -SubjectName para especificar o nome CN do certificado. Isso
# usa como padrão o nome do host do sistema e geralmente não deve ser especificado.

# Escrito por Trond Hindenes <trond@hindenes.com>
# Atualizado por Chris Church <cchurch@ansible.com>
# Atualizado por Michael Crilly <mike@autologic.cm>
# Atualizado por Anton Ouzounov <Anton.Ouzounov@careerbuilder.com>
# Atualizado por Nicolas Simond <contact@nicolas-simond.com>
# Atualizado por Dag Wieërs <dag@wieers.com>
# Atualizado por Jordan Borean <jborean93@gmail.com>
# Atualizado por Erwan Quélin <erwan.quelin@gmail.com>
# Atualizado por David Norman <david@dkn.email>
#
# Versão 1.0 - 2014-07-06
# Versão 1.1 - 2014-11-11
# Versão 1.2 - 2015-05-15
# Versão 1.3 - 2016-04-04
# Versão 1.4 - 2017-01-05
# Versão 1.5 - 2017-02-09
# Versão 1.6 - 2017-04-18
# Versão 1.7 - 2017-11-23
# Versão 1.8 - 2018-02-23
# Versão 1.9 - 2018-09-21

# Suporte para a opção -Verbose
[CmdletBinding()]

Param (
    [string]$SubjectName = $env:COMPUTERNAME,
    [int]$CertValidityDays = 1095,
    [switch]$SkipNetworkProfileCheck,
    $CreateSelfSignedCert = $true,
    [switch]$ForceNewSSLCert,
    [switch]$GlobalHttpFirewallAccess,
    [switch]$DisableBasicAuth = $false,
    [switch]$EnableCredSSP
)

Function Write-ProgressLog {
    $Message = $args[0]
    Write-EventLog -LogName Application -Source $EventSource -EntryType Information -EventId 1 -Message $Message
}

Function Write-VerboseLog {
    $Message = $args[0]
    Write-Verbose $Message
    Write-ProgressLog $Message
}

Function Write-HostLog {
    $Message = $args[0]
    Write-Output $Message
    Write-ProgressLog $Message
}

Function New-LegacySelfSignedCert {
    Param (
        [string]$SubjectName,
        [int]$ValidDays = 1095
    )

    $hostnonFQDN = $env:computerName
    $hostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).Hostname
    $SignatureAlgorithm = "SHA256"

    $name = New-Object -COM "X509Enrollment.CX500DistinguishedName.1"
    $name.Encode("CN=$SubjectName", 0)

    $key = New-Object -COM "X509Enrollment.CX509PrivateKey.1"
    $key.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
    $key.KeySpec = 1
    $key.Length = 4096
    $key.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
    $key.MachineContext = 1
    $key.Create()

    $serverauthoid = New-Object -COM "X509Enrollment.CObjectId.1"
    $serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
    $ekuoids = New-Object -COM "X509Enrollment.CObjectIds.1"
    $ekuoids.Add($serverauthoid)
    $ekuext = New-Object -COM "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
    $ekuext.InitializeEncode($ekuoids)

    $cert = New-Object -COM "X509Enrollment.CX509CertificateRequestCertificate.1"
    $cert.InitializeFromPrivateKey(2, $key, "")
    $cert.Subject = $name
    $cert.Issuer = $cert.Subject
    $cert.NotBefore = (Get-Date).AddDays(-1)
    $cert.NotAfter = $cert.NotBefore.AddDays($ValidDays)

    $SigOID = New-Object -ComObject X509Enrollment.CObjectId
    $SigOID.InitializeFromValue(([Security.Cryptography.Oid]$SignatureAlgorithm).Value)

    [string] $AlternativeName += $hostnonFQDN
    $AlternativeName += $hostFQDN
    $IAlternativeNames = New-Object -ComObject X509Enrollment.CAlternativeNames

    foreach ($AN in $AlternativeName) {
        $AltName = New-Object -ComObject X509Enrollment.CAlternativeName
        $AltName.InitializeFromString(0x3, $AN)
        $IAlternativeNames.Add($AltName)
    }

    $SubjectAlternativeName = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
    $SubjectAlternativeName.InitializeEncode($IAlternativeNames)

[String[]]$KeyUsage = ("DigitalSignature", "KeyEncipherment")
$KeyUsageFlags = 0
foreach ($usage in $KeyUsage) {
    $KeyUsageFlags += [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::$usage
}

$KeyUsageObj = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
$KeyUsageObj.InitializeEncode($KeyUsageFlags)
$KeyUsageObj.Critical = $true

    $cert.X509Extensions.Add($KeyUsageObj)
    $cert.X509Extensions.Add($ekuext)
    $cert.SignatureInformation.HashAlgorithm = $SigOID
    $CERT.X509Extensions.Add($SubjectAlternativeName)
    $cert.Encode()

    $enrollment = New-Object -COM "X509Enrollment.CX509Enrollment.1"
    $enrollment.InitializeFromRequest($cert)
    $certdata = $enrollment.CreateRequest(0)
    $enrollment.InstallResponse(2, $certdata, 0, "")

    # extrai/retorna o thumbprint do certificado gerado
    $parsed_cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $parsed_cert.Import([System.Text.Encoding]::UTF8.GetBytes($certdata))

    return $parsed_cert.Thumbprint
}

Function Enable-GlobalHttpFirewallAccess {
    Write-Verbose "Forçando acesso global ao firewall HTTP"
    # esta é uma implementação bastante ingênua; poderia ser mais sofisticada sobre correspondência/colapso de regras
    $fw = New-Object -ComObject HNetCfg.FWPolicy2

    # tenta encontrar/ativar a regra padrão primeiro
    $add_rule = $false
    $matching_rules = $fw.Rules | Where-Object { $_.Name -eq "Windows Remote Management (HTTP-In)" }
    $rule = $null
    If ($matching_rules) {
        If ($matching_rules -isnot [Array]) {
            Write-Verbose "Editando regra de firewall HTTP única existente"
            $rule = $matching_rules
        }
        Else {
            # tenta encontrar uma com o perfil All ou Public primeiro
            Write-Verbose "Encontradas várias regras de firewall HTTP existentes..."
            $rule = $matching_rules | ForEach-Object { $_.Profiles -band 4 }[0]

            If (-not $rule -or $rule -is [Array]) {
                Write-Verbose "Editando uma regra de firewall HTTP única arbitrária (várias existiam)"
                # bem, escolha a primeira
                $rule = $matching_rules[0]
            }
        }
    }

    If (-not $rule) {
        Write-Verbose "Criando uma nova regra de firewall HTTP"
        $rule = New-Object -ComObject HNetCfg.FWRule
        $rule.Name = "Windows Remote Management (HTTP-In)"
        $rule.Description = "Regra de entrada para o Gerenciamento Remoto do Windows via WS-Management. [TCP 5985]"
        $add_rule = $true
    }

    $rule.Profiles = 0x7FFFFFFF
    $rule.Protocol = 6
    $rule.LocalPorts = 5985
    $rule.RemotePorts = "*"
    $rule.LocalAddresses = "*"
    $rule.RemoteAddresses = "*"
    $rule.Enabled = $true
    $rule.Direction = 1
    $rule.Action = 1
    $rule.Grouping = "Windows Remote Management"

    If ($add_rule) {
        $fw.Rules.Add($rule)
    }

    Write-Verbose "Regra de firewall HTTP $($rule.Name) atualizada"
}

# Configurar tratamento de erros.
Trap {
    $_
    Exit 1
}
$ErrorActionPreference = "Stop"

# Obter o ID e a entidade de segurança da conta de usuário atual
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

# Obter a entidade de segurança para a função de Administrador
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

# Verificar se estamos executando atualmente "como Administrador"
if (-Not $myWindowsPrincipal.IsInRole($adminRole)) {
    Write-Output "ERRO: Você precisa de privilégios elevados de Administrador para executar este script."
    Write-Output "       Inicie o Windows PowerShell usando a opção Executar como administrador."
    Exit 2
}

$EventSource = $MyInvocation.MyCommand.Name
If (-Not $EventSource) {
    $EventSource = "Powershell CLI"
}

If ([System.Diagnostics.EventLog]::Exists('Application') -eq $False -or [System.Diagnostics.EventLog]::SourceExists($EventSource) -eq $False) {
    New-EventLog -LogName Application -Source $EventSource
}

# Detectar a versão do PowerShell.
If ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-ProgressLog "A versão 3 ou superior do PowerShell é necessária."
    Throw "A versão 3 ou superior do PowerShell é necessária."
}

# Encontrar e iniciar o serviço WinRM.
Write-Verbose "Verificando o serviço WinRM."
If (!(Get-Service "WinRM")) {
    Write-ProgressLog "Não foi possível encontrar o serviço WinRM."
    Throw "Não foi possível encontrar o serviço WinRM."
}
ElseIf ((Get-Service "WinRM").Status -ne "Running") {
    Write-Verbose "Configurando o serviço WinRM para iniciar automaticamente na inicialização."
    Set-Service -Name "WinRM" -StartupType Automatic
    Write-ProgressLog "Configurado o serviço WinRM para iniciar automaticamente na inicialização."
    Write-Verbose "Iniciando o serviço WinRM."
    Start-Service -Name "WinRM" -ErrorAction Stop
    Write-ProgressLog "Iniciado o serviço WinRM."
}

Else {
    # Serviço WinRM já está em execução, não precisa fazer nada
}

# WinRM deve estar em execução; verifique se temos uma configuração de sessão PS.
If (!(Get-PSSessionConfiguration -Verbose:$false) -or (!(Get-ChildItem WSMan:\localhost\Listener))) {
    If ($SkipNetworkProfileCheck) {
        Write-Verbose "Habilitando o PS Remoting sem verificar o perfil de rede."
        Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop
        Write-ProgressLog "PS Remoting habilitado sem verificar o perfil de rede."
    }
    Else {
        Write-Verbose "Habilitando o PS Remoting."
        Enable-PSRemoting -Force -ErrorAction Stop
        Write-ProgressLog "PS Remoting habilitado."
    }
}
Else {
    Write-Verbose "O PS Remoting já está habilitado."
}

# Certifique-se de que LocalAccountTokenFilterPolicy esteja definido como 1
# https://github.com/ansible/ansible/issues/42978
$token_path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$token_prop_name = "LocalAccountTokenFilterPolicy"
$token_key = Get-Item -Path $token_path
$token_value = $token_key.GetValue($token_prop_name, $null)
if ($token_value -ne 1) {
    Write-Verbose "Definindo LocalAccountTOkenFilterPolicy como 1"
    if ($null -ne $token_value) {
        Remove-ItemProperty -Path $token_path -Name $token_prop_name
    }
    New-ItemProperty -Path $token_path -Name $token_prop_name -Value 1 -PropertyType DWORD > $null
}

# Certifique-se de que haja um ouvinte SSL.
$listeners = Get-ChildItem WSMan:\localhost\Listener
If (!($listeners | Where-Object { $_.Keys -like "TRANSPORT=HTTPS" })) {
    # Não podemos usar New-SelfSignedCertificate no 2012R2 e versões anteriores
  	$thumbprint = New-LegacySelfSignedCert -SubjectName $SubjectName -ValidDays $CertValidityDays
  	Write-HostLog "Certificado SSL autoassinado gerado; thumbprint: $thumbprint"

  	# Crie as tabelas de hash de configurações a serem usadas.
  	$valueset = @{
  		Hostname = $SubjectName
  		CertificateThumbprint = $thumbprint
  	}

  	$selectorset = @{
  		Transport = "HTTPS"
  		Address = "*"
  	}

  	Write-Verbose "Habilitando o ouvinte SSL."
  	New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ValueSet $valueset
  	Write-ProgressLog "Ouvinte SSL habilitado."
}
Else {
  	Write-Verbose "O ouvinte SSL já está ativo."

  	# Force um novo certificado SSL no Listener se $ForceNewSSLCert
  	If ($ForceNewSSLCert) {

  		# Não podemos usar New-SelfSignedCertificate no 2012R2 e versões anteriores
  		$thumbprint = New-LegacySelfSignedCert -SubjectName $SubjectName -ValidDays $CertValidityDays
  		Write-HostLog "Certificado SSL autoassinado gerado; thumbprint: $thumbprint"

  		$valueset = @{
  			CertificateThumbprint = $thumbprint
  			Hostname = $SubjectName
  		}

  		# Excluir o ouvinte para SSL
  		$selectorset = @{
  			Address = "*"
  			Transport = "HTTPS"
  		}
  		Remove-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset

  		# Adicionar novo Listener com novo certificado SSL
  		New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ValueSet $valueset
  	}
}

# Verificar a autenticação básica.
$basicAuthSetting = Get-ChildItem WSMan:\localhost\Service\Auth | Where-Object { $_.Name -eq "Basic" }

If ($DisableBasicAuth) {
  	If (($basicAuthSetting.Value) -eq $true) {
  		Write-Verbose "Desabilitando o suporte de autenticação básica."
  		Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $false
  		Write-ProgressLog "Suporte de autenticação básica desabilitado."
  	}
  	Else {
  		Write-Verbose "A autenticação básica já está desabilitada."
  	}
}
Else {
  	If (($basicAuthSetting.Value) -eq $false) {
  		Write-Verbose "Habilitando o suporte de autenticação básica."
  		Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true
  		Write-ProgressLog "Suporte de autenticação básica habilitado."
  	}
  	Else {
  		Write-Verbose "A autenticação básica já está habilitada."
  	}
}

# Se EnableCredSSP estiver definido como verdadeiro
If ($EnableCredSSP) {
  	# Verificar a autenticação CredSSP
  	$credsspAuthSetting = Get-ChildItem WSMan:\localhost\Service\Auth | Where-Object { $_.Name -eq "CredSSP" }
  	If (($credsspAuthSetting.Value) -eq $false) {
  		Write-Verbose "Habilitando o suporte de autenticação CredSSP."
  		Enable-WSManCredSSP -role server -Force
  		Write-ProgressLog "Suporte de autenticação CredSSP habilitado."
  	}
}

If ($GlobalHttpFirewallAccess) {
  	Enable-GlobalHttpFirewallAccess
}

# Configurar o firewall para permitir conexões HTTPS WinRM.
$fwtest1 = netsh advfirewall firewall show rule name="Allow WinRM HTTPS"
$fwtest2 = netsh advfirewall firewall show rule name="Allow WinRM HTTPS" profile=any
If ($fwtest1.count -lt 5) {
  	Write-Verbose "Adicionando regra de firewall para permitir HTTPS WinRM."
  	netsh advfirewall firewall add rule profile=any name="Allow WinRM HTTPS" dir=in localport=5986 protocol=TCP action=allow
  	Write-ProgressLog "Regra de firewall adicionada para permitir HTTPS WinRM."
}
ElseIf (($fwtest1.count -ge 5) -and ($fwtest2.count -lt 5)) {
  	Write-Verbose "Atualizando a regra de firewall para permitir HTTPS WinRM para qualquer perfil."
  	netsh advfirewall firewall set rule name="Allow WinRM HTTPS" new profile=any
  	Write-ProgressLog "Regra de firewall atualizada para permitir HTTPS WinRM para qualquer perfil."
}
Else {
  	Write-Verbose "A regra de firewall já existe para permitir HTTPS WinRM."
}

# Testar uma conexão de comunicação remota com o host local, que deve funcionar.
$httpResult = Invoke-Command -ComputerName "localhost" -ScriptBlock { $using:env:COMPUTERNAME } -ErrorVariable httpError -ErrorAction SilentlyContinue
$httpsOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck

$httpsResult = New-PSSession -UseSSL -ComputerName "localhost" -SessionOption $httpsOptions -ErrorVariable httpsError -ErrorAction SilentlyContinue

If ($httpResult -and $httpsResult) {
  	Write-Verbose "HTTP: Habilitado | HTTPS: Habilitado"
}
ElseIf ($httpsResult -and !$httpResult) {
  	Write-Verbose "HTTP: Desabilitado | HTTPS: Habilitado"
}
Else {
  	Write-ProgressLog "Não é possível estabelecer uma sessão de comunicação remota HTTP ou HTTPS."
  	Throw "Não é possível estabelecer uma sessão de comunicação remota HTTP ou HTTPS."
}
Write-VerboseLog "O PS Remoting foi configurado com sucesso para o Ansible."