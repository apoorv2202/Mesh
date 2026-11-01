using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace VaderRecovery {
 public static class ConsoleProbe {
  [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
  static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)]
  static extern bool GetConsoleMode(SafeFileHandle handle,out uint mode);
  public static bool Available() {
   if(Console.IsInputRedirected || Console.IsOutputRedirected) return false;
   // Verify the same CONIN$/CONOUT$ access needed by PostgreSQL's no-echo prompt.
   using(var input=CreateFile("CONIN$",0xC0000000,3,IntPtr.Zero,3,0,IntPtr.Zero))
   using(var output=CreateFile("CONOUT$",0xC0000000,3,IntPtr.Zero,3,0,IntPtr.Zero)) {
    uint mode;
    return !input.IsInvalid && !output.IsInvalid && GetConsoleMode(input,out mode) && GetConsoleMode(output,out mode);
   }
  }
 }
}
