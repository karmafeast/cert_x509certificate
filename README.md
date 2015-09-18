# karmafeast-cert_x509certificate

x509 .cer file import to cert stores on windows via powershell.  

**removal via ensure => absent and thumbprint match.**  

**need cert thumbprint for unless comparison in ensure => present unless file provided**

example use:
    
    class dogfood{
    
    cert_x509certificate::import { 'intermediate CA cert':
    	certpath  => "c:\\temp\\mycert.cer",
    	certrootstore => 'LocalMachine',
    	certstore => 'CA',
    	ensure=> 'present',
      }
    
    cert_x509certificate::import { 'remove old cert':
    	certrootstore => 'LocalMachine',
    	certstore => 'My',
    	ensure=> 'absent',
    	thumbprint=> '4111F03333C8942222229B277777772350002A97',
      }
    
    }
