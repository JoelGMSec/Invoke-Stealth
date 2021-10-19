<p align="center"><img width=650 alt="Invoke-Stealth" src="https://raw.githubusercontent.com/JoelGMSec/Invoke-Stealth/master/Design/Invoke-Stealth.png"></p>

**Invoke-Stealth** is a Simple & Powerful PowerShell Script Obfuscator.

This tool helps you to automate the obfuscation process of any script written in PowerShell with different techniques. You can use any of them separately, together or all of them sequentially with ease, from Windows or Linux.


# Requirements
- Powershell 4.0 or higher
- Bash*
- Python 3*

*Required to use all features


# Download
It is recommended to clone the complete repository or download the zip file.
You can do this by running the following command:
```
git clone https://github.com/JoelGMSec/Invoke-Stealth.git
```

You can also download the limited version as follows:
```
powershell iwr -useb https://darkbyte.net/invoke-stealth.php -outfile Invoke-Stealth.ps1
```


# Usage
```
.\Invoke-Stealth.ps1 -help

Info:  This tool helps you to automate the obfuscation process of
       any script written in PowerShell with different techniques

Usage: .\Invoke-Stealth.ps1 script.ps1 -technique Chimera
         - You can use as single or separated by commas -

Techniques:
       · Chimera: Substitute strings and concatenate variables
       · BetterXencrypt: Compresses and encrypts with random iterations
       · PyFuscation: Obfuscate functions, variables and parameters
       · PSObfuscation: Convert content to bytes and encode with Gzip
       · ReverseB64: Encode with base64 and reverse it to avoid detections
       · All: Sequentially executes all techniques described above

Warning: The output script will exponentially multiply the original size
         Chimera & PyFuscation need dependencies to work properly in Windows
```

### The detailed guide of use can be found at the following link:

https://darkbyte.net/ofuscando-scripts-de-powershell-con-invoke-stealth


# License
This project is licensed under the GNU 3.0 license - see the LICENSE file for more details.


# Credits and Acknowledgments
This script has been created and designed from scratch by Joel Gámez Molina // @JoelGMSec

Some modules use third-party code, scripts, and tools, particularly:

• **Chimera** by *tokyoneon* --> https://github.com/tokyoneon/Chimera

• **BetterXencrypt** by *GetRektBoy724* --> https://github.com/GetRektBoy724/BetterXencrypt

• **PyFuscation** by *CBHue* --> https://github.com/CBHue/PyFuscation

• **PSObfuscation** by *gh0x0st* --> https://github.com/gh0x0st/Invoke-PSObfuscation


# Contact
This software does not offer any kind of guarantee. Its use is exclusive for educational environments and / or security audits with the corresponding consent of the client. I am not responsible for its misuse or for any possible damage caused by it.

For more information, you can find me on Twitter as [@JoelGMSec](https://twitter.com/JoelGMSec) and on my blog [darkbyte.net](https://darkbyte.net).


# Support
You can support my work buying me a coffee:

[<img width=250 alt="buymeacoffe" src="https://cdn.buymeacoffee.com/buttons/v2/default-blue.png">](https://www.buymeacoffee.com/joelgmsec)
