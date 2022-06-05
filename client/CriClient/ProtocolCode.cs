namespace CriClient
{
    class ProtocolCode
    {
        public string Value { get; private set; }
        private ProtocolCode(string value)
        {
            Value = value;
        }

        public static ProtocolCode Register { get { return new ProtocolCode("00"); } }
        public static ProtocolCode Login { get { return new ProtocolCode("01"); } }
        public static ProtocolCode Logout { get { return new ProtocolCode("02"); } }
        public static ProtocolCode Hello { get { return new ProtocolCode("03"); } }
        public static ProtocolCode Search { get { return new ProtocolCode("04"); } }
        public static ProtocolCode Chat { get { return new ProtocolCode("05"); } }
        public static ProtocolCode Text { get { return new ProtocolCode("06"); } }
        public static ProtocolCode GroupCreate { get { return new ProtocolCode("07"); } }
        public static ProtocolCode GroupSearch { get { return new ProtocolCode("08"); } }
        public static ProtocolCode GroupText { get { return new ProtocolCode("09"); } }

        public override string ToString()
        {
            return Value;
        }

        public override bool Equals(object obj)
        {
            if (obj is string)
            {
                return Value == obj.ToString();
            }
            if (obj is not ProtocolCode protocolCode)
            {
                return false;
            }

            return Value == protocolCode.Value;
        }
    }
}
