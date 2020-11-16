using System;

namespace Encrypt.Argon2
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Informe a senha a ser criptografada:");
            var senha = Console.ReadLine();
            Console.WriteLine($"Senha a ser testada: {senha}");

            Console.WriteLine("\nInforme quantos loops (criptografar senha) você quer:");
            var loops = Console.ReadLine();

            Console.WriteLine("\nAgora quanto aos parâmetros de criptografia.");
            Console.WriteLine("Informe o grau de paralelismo:");
            var paralelismo = Console.ReadLine();

            Console.WriteLine("Informe quantas iterações o algoritmo realizará:");
            var interacoes = Console.ReadLine();

            Console.WriteLine("Informe o tamanho da memória utilizada em kB (1024 kB=1mb):");
            var memoriaTamanho = Console.ReadLine();

            Console.WriteLine("\nInforme o caminho para salvar o log.");
            var ambiente = Console.ReadLine();

            Password.Argon2Hash(senha, int.Parse(paralelismo), int.Parse(interacoes), int.Parse(memoriaTamanho), int.Parse(loops), ambiente);

            Console.ReadKey();
        }
    }
}