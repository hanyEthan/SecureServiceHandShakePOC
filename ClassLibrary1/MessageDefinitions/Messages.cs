namespace Common.MessageDefinitions
{
    public class KeyPair
    {
        public string? PublicKey { get; set; }
        public string? PrivateKey { get; set; }
    }
    public class InitiateActivationRequest
    {
        public string? DeviceId { get; set; }
        public string? K1PublicKey { get; set; }
    }
    public class InitiateActivationResponse
    {
        public KeyPair? K2 { get; set; }
        public string? C1 { get; set; }
        public string? C2 { get; set; }
    }
    public class LoginActivationRequest
    {
        public string? DeviceId { get; set; }
    }
    public class LoginActivationResponse : ChallengeRequest
    {
    }
    public class LoginVerificationRequest : ChallengeResponse
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
    }
    public class LoginVerificationResponse
    {
        public bool Success { get; set; }
    }
    public class ChallengeRequest
    {
        public string? Challenge { get; set; }
    }
    public class ChallengeResponse
    {
        public string? DeviceId { get; set; }
        public string? Challenge { get; set; }
        public string? ChallengeSignature { get; set; }
    }
}
