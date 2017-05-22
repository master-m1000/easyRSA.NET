Imports System.Security.Cryptography
Imports System.Text

Public Class easyRSA_NET

    Structure KeyPair
        ''' <summary>
        ''' Public key as XML
        ''' </summary>
        ''' <returns></returns>
        Property publicKey As String

        ''' <summary>
        ''' Private key as XML
        ''' </summary>
        ''' <returns></returns>
        Property privateKey As String
    End Structure


    ''' <summary>
    ''' Creates a random RSA key pair.
    ''' </summary>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns>Returns a key pair</returns>
    Function CreateKeyPair(ByVal keysize As Integer) As KeyPair
        Dim rsaKey As New KeyPair 'Declare return varible
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declare RSA service and generate random key pair
        rsaKey.publicKey = rsaCryptoProvider.ToXmlString(False) 'Public key to XML
        rsaKey.privateKey = rsaCryptoProvider.ToXmlString(True) 'Private key to XML
        rsaCryptoProvider.Dispose() 'Deallocate ressources
        Return rsaKey
    End Function

    ''' <summary>
    ''' Generates the public key by the private key.
    ''' </summary>
    ''' <param name="privateKeyXml">Private key as XML</param>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns>Returns the public key</returns>
    Function GeneratePublicKeyWithPrivateKey(ByVal privateKeyXml As String, ByVal keysize As Integer) As String
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declare RSA service
        Dim publicKey As String = String.Empty 'Declare return varible
        rsaCryptoProvider.FromXmlString(privateKeyXml) 'RSA service receives private key
        publicKey = rsaCryptoProvider.ToXmlString(False) 'Public key to XML
        rsaCryptoProvider.Dispose() 'Deallocate ressources
        Return publicKey
    End Function

    ''' <summary>
    ''' Encrypts a Byte Array.
    ''' </summary>
    ''' <param name="DATA">Byte Array to encrypt</param>
    ''' <param name="publicKeyXml">Public key as XML</param>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns>Encrypted Byte Array</returns>
    Function Encrypt(ByVal DATA As Byte(), ByVal publicKeyXml As String, ByVal keysize As Integer) As Byte()
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declare RSA service
        Dim encryptedDATA As Byte() = {0} 'Declare return value
        rsaCryptoProvider.FromXmlString(publicKeyXml) 'RSA service receives public key
        encryptedDATA = rsaCryptoProvider.Encrypt(DATA, True) 'Encrypts data and write it into a Base64 string
        rsaCryptoProvider.Dispose() 'Deallocate ressources
        Return encryptedDATA
    End Function

    ''' <summary>
    ''' Encrypts a String.
    ''' </summary>
    ''' <param name="DATA">String to encrypt</param>
    ''' <param name="publicKeyXml">Public key as XML</param>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns>Encrypted String</returns>
    Function Encrypt(ByVal DATA As String, ByVal publicKeyXml As String, ByVal keysize As Integer) As String
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declare RSA service
        Dim byteData As Byte() = Encoding.UTF8.GetBytes(DATA)  'Write data string into a Byte Array
        Dim encryptedString As String = String.Empty 'Declare return value
        rsaCryptoProvider.FromXmlString(publicKeyXml) 'RSA service receives public key
        encryptedString = Convert.ToBase64String(rsaCryptoProvider.Encrypt(byteData, True)) 'Encrypts data and write it into a Base64 string
        rsaCryptoProvider.Dispose() 'Deallocate ressources
        Return encryptedString
    End Function

    ''' <summary>
    ''' Decrypts a Byte Array.
    ''' </summary>
    ''' <param name="DATA">Byte Array to dencrypt</param>
    ''' <param name="privateKeyXml">Private key as XML</param>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns>Decrypted Byte Array</returns>
    Function Decrypt(ByVal DATA As Byte(), ByVal privateKeyXml As String, ByVal keysize As Integer) As Byte()
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declare RSA service
        Dim decryptedDATA As Byte() = {0} 'Declare return value
        rsaCryptoProvider.FromXmlString(privateKeyXml) 'RSA service receives private key
        decryptedDATA = rsaCryptoProvider.Decrypt(DATA, True) 'Encrypts data and write it into the return value
        rsaCryptoProvider.Dispose() 'Deallocate ressources
        Return decryptedDATA
    End Function

    ''' <summary>
    ''' Decrypts a String.
    ''' </summary>
    ''' <param name="DATA">String to dencrypt</param>
    ''' <param name="privateKeyXml">Private key as XML</param>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns>Decrypted String</returns>
    Function Decrypt(ByVal DATA As String, ByVal privateKeyXml As String, ByVal keysize As Integer) As String
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declare RSA service
        Dim byteData As Byte() = Convert.FromBase64String(DATA) 'Write data Base64 string into a Byte Array
        Dim decryptedString As String = String.Empty 'Declare return value
        rsaCryptoProvider.FromXmlString(privateKeyXml) 'RSA service receives private key
        decryptedString = Encoding.Default.GetString(rsaCryptoProvider.Decrypt(byteData, True)) 'Encrypts data and write it into the return value
        rsaCryptoProvider.Dispose() 'Deallocate ressources
        Return decryptedString
    End Function

    ''' <summary>
    ''' Signs a Byte Array.
    ''' </summary>
    ''' <param name="DATA">Byte Array to sign</param>
    ''' <param name="privateKeyXml">Private key as XML</param>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns>Signed hash of the Data</returns>
    Public Function Sign(ByVal DATA As Byte(), ByVal privateKeyXml As String, ByVal keysize As Integer) As Byte()
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declare RSA service
        rsaCryptoProvider.FromXmlString(privateKeyXml) 'RSA service receives private key
        Dim signature As Byte() = rsaCryptoProvider.SignData(DATA, GetType(SHA512))
        rsaCryptoProvider.Dispose() 'Deallocate ressources
        Return signature
    End Function

    ''' <summary>
    ''' Sings a String.
    ''' </summary>
    ''' <param name="DATA">String to sign</param>
    ''' <param name="privateKeyXml">Private key as XML</param>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns>Signed hash of the String</returns>
    Public Function Sign(ByVal DATA As String, ByVal privateKeyXml As String, ByVal keysize As Integer) As Byte()
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declare RSA service
        rsaCryptoProvider.FromXmlString(privateKeyXml) 'RSA service receives private key
        Dim byteData As Byte() = Convert.FromBase64String(DATA) 'Write data Base64 string into a Byte Array
        Dim signature As Byte() = rsaCryptoProvider.SignData(byteData, GetType(SHA512))
        rsaCryptoProvider.Dispose() 'Deallocate ressources
        Return signature
    End Function

    ''' <summary>
    ''' Verifies a Byte Array.
    ''' </summary>
    ''' <param name="DATA">Byte Array to verify</param>
    ''' <param name="publicKeyXml">Public key as XML</param>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns>Returns true if the Byte Array could be verified</returns>
    Public Function Verify(ByVal DATA As Byte(), ByVal SIGNATURE As Byte(), ByVal publicKeyXml As String, ByVal keysize As Integer) As Boolean
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declare RSA service
        rsaCryptoProvider.FromXmlString(publicKeyXml) 'RSA service receives private key
        Dim verification As Boolean = rsaCryptoProvider.VerifyData(DATA, GetType(SHA512), SIGNATURE)
        rsaCryptoProvider.Dispose() 'Deallocate ressources
        Return verification
    End Function

    ''' <summary>
    ''' Verifies a String.
    ''' </summary>
    ''' <param name="DATA">String to verify</param>
    ''' <param name="publicKeyXml">Public key as XML</param>
    ''' <param name="keysize">Key size as a power of 2, e.g. 2048 or 4096</param>
    ''' <returns>Returns true if the String could be verified</returns>
    Public Function Verify(ByVal DATA As String, ByVal SIGNATURE As Byte(), ByVal publicKeyXml As String, ByVal keysize As Integer) As Boolean
        Dim rsaCryptoProvider As New RSACryptoServiceProvider(keysize) 'Declare RSA service
        Dim byteData As Byte() = Convert.FromBase64String(DATA) 'Write data Base64 string into a Byte Array
        rsaCryptoProvider.FromXmlString(publicKeyXml) 'RSA service receives private key
        Dim verification As Boolean = rsaCryptoProvider.VerifyData(byteData, GetType(SHA512), SIGNATURE)
        rsaCryptoProvider.Dispose() 'Deallocate ressources
        Return verification
    End Function
End Class
