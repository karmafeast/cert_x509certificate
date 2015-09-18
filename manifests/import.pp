# import an x509 certificate
# certstore -
# AddressBook          X.509 certificate store for other users.
# AuthRoot             X.509 certificate store for third-party certificate authorities (CAs).
# CA                   X.509 certificate store for intermediate certificate authorities (CAs).
# Disallowed           X.509 certificate store for revoked certificates.
# My                   X.509 certificate store for personal certificates.
# Root                 X.509 certificate store for trusted root certificate authorities (CAs).
# TrustedPeople        X.509 certificate store for directly trusted people and resources.
# TrustedPublisher     X.509 certificate store for directly trusted publishers.
define cert_x509certificate::import (
  $certpath      = '', # path to certificate file to import
  $certrootstore = 'LocalMachine',
  $certstore     = 'My',
  $ensure        = 'present',
  $thumbprint    = '', # thumbprint used for remove if not have file
  $certpassword  = '',) {
  validate_re($ensure, '^(present|import|absent)$', 'ensure must be one of \'present\', \'import\', \'absent\'')
  validate_re($certrootstore, '^(LocalMachine|CurrentUser)$', 'certrootstore must be one of \'LocalMachine\', \'CurrentUser\'')
  validate_re($certstore, '^(AddressBook|AuthRoot|CA|Disallowed|My|Root|TrustedPeople|TrustedPublisher)$', 'certstore must be one of \'AddressBook\', \'AuthRoot\', \'CA\', \'Disallowed\', \'My\', \'Root\', \'TrustedPeople\', \'TrustedPublisher\''
  )

  if ($ensure in [
    'present',
    'import']) {
    if (empty($certpath)) {
      fail('cannot ensure present when certpath empty')
    }

    if (empty($certpassword)) {
      exec { "IMPORT CERT FROM X509 .cer file - ${certpath} - ${title}":
        command   => "\$pfx = new-object System.Security.Cryptography.X509Certificates.X509Certificate2;\$pfx.import(\"${certpath}\");\$store = new-object System.Security.Cryptography.X509Certificates.X509Store(\"${certstore}\",\"${certrootstore}\");\$store.open(\"MaxAllowed\");\$store.add(\$pfx);\$store.close();",
        provider  => powershell,
        unless    => "\$pfx = new-object System.Security.Cryptography.X509Certificates.X509Certificate2;\$pfx.import(\"${certpath}\");\$store = new-object System.Security.Cryptography.X509Certificates.X509Store(\"${certstore}\",\"${certrootstore}\");\$store.open(\"MaxAllowed\");\$found = \$false;foreach(\$c in \$store.Certificates){if(\$c.thumbprint -eq \$pfx.Thumbprint){\$found = \$true;break;}}if(\$found){exit 0;}else{exit 1;}",
        logoutput => true,
      }
    } else {
      exec { "IMPORT CERT FROM X509 .cer file with PW - ${certpath} - ${title}":
        command   => "\$pfx = new-object System.Security.Cryptography.X509Certificates.X509Certificate2;\$pfxPass = ConvertTo-SecureString -String \"${certpassword}\" -AsPlainText -Force;\$pfx.import(\"${certpath}\",\"${certpassword}\",“Exportable,PersistKeySet”);\$store = new-object System.Security.Cryptography.X509Certificates.X509Store(\"${certstore}\",\"${certrootstore}\");\$store.open(\"MaxAllowed\");\$store.add(\$pfx);\$store.close();",
        provider  => powershell,
        unless    => "\$pfx = new-object System.Security.Cryptography.X509Certificates.X509Certificate2;\$pfx.import(\"${certpath}\");\$store = new-object System.Security.Cryptography.X509Certificates.X509Store(\"${certstore}\",\"${certrootstore}\");\$store.open(\"MaxAllowed\");\$found = \$false;foreach(\$c in \$store.Certificates){if(\$c.thumbprint -eq \$pfx.Thumbprint){\$found = \$true;break;}}if(\$found){exit 0;}else{exit 1;}",
        logoutput => true,
      }

    }

  }

  # string validation on others is going to be in the 'absent' category - reset to defaults
   else {
    if (empty($thumbprint)) # no thumbprint for remove must have file in this case for comparison thumbprint
    {
      if (empty($certpath)) # no file either - fail
      {
        fail('cannot ensure absent when no comparison thumbprint and no file for obtaining one from')
      }

      # get comparison thumbprint from file, if match remove cert
      exec { "REMOVE CERT BY MATCH THUMBPRINT IN X509 .cer file - ${certpath} - ${title}":
        command   => "\$pfx = new-object System.Security.Cryptography.X509Certificates.X509Certificate2;\$pfx.import(\"${certpath}\");\$store = new-object System.Security.Cryptography.X509Certificates.X509Store(\"${certstore}\",\"${certrootstore}\");\$store.open(\"MaxAllowed\");\$store.Remove(\$pfx);\$store.close();",
        provider  => powershell,
        unless    => "\$pfx = new-object System.Security.Cryptography.X509Certificates.X509Certificate2;\$pfx.import(\"${certpath}\");\$store = new-object System.Security.Cryptography.X509Certificates.X509Store(\"${certstore}\",\"${certrootstore}\");\$store.open(\"MaxAllowed\");\$found = \$false;foreach(\$c in \$store.Certificates){if(\$c.thumbprint -eq \$pfx.Thumbprint){\$found = \$true;break;}}if(\$found){exit 1;}else{exit 0;}",
        logoutput => true,
      }

    } else {
      # remove cert if thumbprint match
      exec { "REMOVE CERT BY MATCH THUMBPRINT - ${thumbprint} - ${title}":
        command   => "\$store = new-object System.Security.Cryptography.X509Certificates.X509Store(\"${certstore}\",\"${certrootstore}\");\$store.open(\"MaxAllowed\");foreach(\$c in \$store.Certificates){if(\$c.thumbprint -eq \"${thumbprint}\"){\$store.Remove(\$c);break;}}",
        provider  => powershell,
        unless    => "\$store = new-object System.Security.Cryptography.X509Certificates.X509Store(\"${certstore}\",\"${certrootstore}\");\$store.open(\"MaxAllowed\");\$found = \$false;foreach(\$c in \$store.Certificates){if(\$c.thumbprint -eq \"${thumbprint}\"){\$found = \$true;break;}}if(\$found){exit 1;}else{exit 0;}",
        logoutput => true,
      }
    }
  }

}
