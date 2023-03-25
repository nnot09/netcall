using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace netcall
{
    internal static class ConsoleEx
    {
        public static bool Enabled { get; set; } = true;
        public static void DisableLogging()
            => Enabled = false;

        public static void WriteLine(string text)
        {
            if (!Enabled)
                return;

            WritePrefix(ConsoleState.Info);

            Console.WriteLine(text);
        }

        public static void WriteLine(string text, params object?[]? arg)
        {
            if (!Enabled)
                return;

            WritePrefix(ConsoleState.Info);

            Console.WriteLine(text, arg);
        }

        public static void WriteLine(ConsoleState state, string text)
        {
            if (!Enabled)
                return;

            WritePrefix(state);

            Console.WriteLine(text);
        }

        public static void WriteLine(ConsoleState state, string text, params object?[]? arg)
        {
            if (!Enabled)
                return;

            WritePrefix(state);

            Console.WriteLine(text, arg);
        }

        private static void WritePrefix(ConsoleState state)
        {
            var colorandprefix = GetColorAndPrefix(state);

            int padding = 10;
            int totalPadding = padding - colorandprefix.Prefix.Length;

            Console.Write("[");

            Console.ForegroundColor = colorandprefix.Color;

            Console.Write(colorandprefix.Prefix);

            Console.ResetColor();

            Console.Write("]");

            for (int i = 0; i < totalPadding; i++)
                Console.Write(" ");
        }

        private static (ConsoleColor Color, string Prefix) GetColorAndPrefix(ConsoleState state)
        {
            string prefix = "info";
            ConsoleColor color = ConsoleColor.White;

            switch (state)
            {
                case ConsoleState.Info:
                    prefix = "info";
                    break;
                case ConsoleState.Alert:
                    prefix = "alert";
                    color = ConsoleColor.Yellow;
                    break;
                case ConsoleState.Action:
                    prefix = "action";
                    color = ConsoleColor.Cyan;
                    break; ;
                case ConsoleState.Success:
                    prefix = "success";
                    color = ConsoleColor.Green;
                    break;
                case ConsoleState.Failed:
                    prefix = "fail";
                    color = ConsoleColor.Red;
                    break;

                default:
                    prefix = "info";
                    break;
            }

            return (color, prefix);
        }
    }
}
