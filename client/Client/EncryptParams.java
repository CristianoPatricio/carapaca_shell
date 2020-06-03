
public class EncryptParams {
    public byte[] ciphertext;
    public byte[] encodedParams;

    public EncryptParams (byte[] ciphertext, byte[] encodedParams) {
        this.ciphertext = ciphertext;
        this.encodedParams = encodedParams;
    }
}
