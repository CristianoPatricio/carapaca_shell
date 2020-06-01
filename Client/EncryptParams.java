

public class EncryptParams {
    private byte[] ciphertext;
    private byte[] encodedParams;

    public EncryptParams (byte[] ciphertext, byte[] encodedParams) {
        this.ciphertext = ciphertext;
        this.encodedParams = encodedParams;
    }
}
