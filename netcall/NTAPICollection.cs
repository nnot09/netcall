namespace netcall
{
    internal class NTAPICollection : List<INTAPI>
    {
        public void AddAPI<T>(string name) where T : Delegate
        {
            this.Add(new NtApi<T>()
            {
                Name = name,
                Type = typeof(T)
            });
        }

        public T GetFunction<T>()
        {
            var type = typeof(T);

            var api = this.FirstOrDefault(i => i.Type == type);

            if ( api == null )
            {
                ConsoleEx.WriteLine(ConsoleState.Failed, "function of type {0} not found.", type.Name);
                return default;
            }

            return ((NtApi<T>)api).Function;
        }
    }
}
