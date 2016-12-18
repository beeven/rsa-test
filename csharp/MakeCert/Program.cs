using System;
using System.Security.Cryptography;

class Program
{
    static void Main(string[] args)
    {
        RSA rsa = RSA.Create();
        Console.WriteLine(rsa.GetType().ToString());
        System.Security.Cryptography.X509Certificates.X509Certificate2 cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(@"d:\dev\rsa\certs\private_key.pem");
        Console.WriteLine(cert.HasPrivateKey);
    }
}