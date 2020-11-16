using Konscious.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Encrypt.Argon2
{
    public class Password
    {
        public static void Argon2Hash(string senha, int paralelismo, int interacoes, int tamanhoMemoria, int loops, string ambiente)
        {
            string path = $@"{ambiente}.txt";

            List<Tuple<string, string, double>> retorno = new List<Tuple<string, string, double>>();

            for (var i = 0; i < loops; i++)
                retorno.Add(CreateHash(senha, paralelismo, interacoes, tamanhoMemoria, path));

            try
            {
                Console.WriteLine("\nCriando log...");

                using (var stream = File.Open(path, FileMode.Append))
                {
                    using (var tw = new StreamWriter(stream))
                    {
                        tw.WriteLine($"Todas as {loops} hashes foram geradas com uma média de {retorno.Select(x => x.Item3).Average()} segundos.");
                        tw.WriteLine($"\n######################################################################################################################################\n");
                        tw.WriteLine($"Senha usada: {senha}");
                        tw.WriteLine($"Quantidade de hashes criadas: {loops}");
                        tw.WriteLine($"Paralelismo: {paralelismo}");
                        tw.WriteLine($"Iterações: {interacoes}");
                        tw.WriteLine($"Tamanho da memória: {tamanhoMemoria / 1000} mB");
                        tw.WriteLine($"\n######################################################################################################################################\n");

                        foreach (var argon2Hash in retorno)
                        {
                            tw.WriteLine($"\nHash - {argon2Hash.Item1}");
                            tw.WriteLine($"Salt - {argon2Hash.Item2}");
                            tw.WriteLine($"{argon2Hash.Item3} segundos para gerar a hash.");
                        }
                    }
                }

                Console.WriteLine($"...Log criado - {path}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro ao gerar log. {ex.Message}");
            }

            Console.WriteLine($"\nTodas as {loops} hashes foram geradas com uma média de {retorno.Select(x => x.Item3).Average()} segundos.");
        }

        private static Tuple<string, string, double> CreateHash(string senha, int paralelismo, int interacoes, int tamanhoMemoria, string path)
        {
            Console.WriteLine("\n...Criando salt/hash");

            var stopwatch = Stopwatch.StartNew();
            var salt = CreateSalt();
            var hash = HashPasswordArgon2(senha, salt, paralelismo, interacoes, tamanhoMemoria);
            stopwatch.Stop();

            var hashBase64 = Convert.ToBase64String(hash);
            var saltBase64 = Convert.ToBase64String(salt);

            Console.WriteLine($"\nHash criada em {stopwatch.ElapsedMilliseconds / 1024.0} segundos.");
            Console.WriteLine($"Hash - {hashBase64}");
            Console.WriteLine($"Salt - {saltBase64}");

            return new Tuple<string, string, double>(hashBase64, saltBase64, stopwatch.ElapsedMilliseconds / 1024.0);
        }

        private static byte[] HashPasswordArgon2(string password, byte[] salt, int paralelismo, int interacoes, int tamanhoMemoria)
        {
            var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));

            argon2.Salt = salt;
            argon2.DegreeOfParallelism = paralelismo;
            argon2.Iterations = interacoes;
            argon2.MemorySize = tamanhoMemoria;

            return argon2.GetBytes(16);
        }

        private static byte[] CreateSalt()
        {
            var buffer = new byte[16];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(buffer);
            return buffer;
        }

        private static bool VerifyHash(string password, byte[] salt, byte[] hash, int paralelismo, int interacoes, int tamanhoMemoria)
        {
            var newHash = HashPasswordArgon2(password, salt, paralelismo, interacoes, tamanhoMemoria);
            return hash.SequenceEqual(newHash);
        }
    }
}