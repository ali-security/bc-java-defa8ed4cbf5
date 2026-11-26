package org.bouncycastle.pkcs.test;

import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePBMac1CalculatorProviderBuilder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class PBETest
    extends TestCase
{
    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testPBESHA256()
        throws Exception
    {
        MacCalculator pbCalculator = new JcePBMac1CalculatorBuilder("HmacSHA256", 256)
            .setIterationCount(1)
            .setSalt(Strings.toByteArray("salt"))
            .setPrf(JcePBMac1CalculatorBuilder.PRF_SHA256)
            .setProvider("BC").build("passwd".toCharArray());

        assertEquals("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc", Hex.toHexString((byte[])pbCalculator.getKey().getRepresentation()));

    }

    // A PBMAC1 protection algorithm whose PBKDF2 iteration count exceeds PBE_MAX_ITERATION_COUNT
    // (default 10_000_000) must be rejected by the JCE PBMAC1 builder before running the KDF, not spin
    // PBKDF2 on the attacker-supplied count - a pre-auth CPU DoS on CMP PBMAC1 verify.
    public void testPbmac1IterationCountCapped() throws Exception {
        AlgorithmIdentifier prf = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, null);
        AlgorithmIdentifier protectionAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBMAC1,
            new PBMAC1Params(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params("salt".getBytes(), 10000001, 32, prf)),
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, null)
            )
        );
        try {
            new JcePBMac1CalculatorProviderBuilder().setProvider(new BouncyCastleProvider())
                .build().get(protectionAlgorithm, "foobar123".toCharArray());
            fail("PBMAC1 iteration count above the cap should be rejected");
        } catch (OperatorCreationException e) {
            assertTrue(e.getMessage().contains("iteration count"));
        }
    }

    // The PBKDF2 keyLength of a PBMAC1 protection algorithm sizes the derivation output and arrives
    // with the same unauthenticated parameters as the iteration count, so the JCE PBMAC1 builder must
    // bound it before deriving; 268435456 also makes keyLength * 8 overflow to a negative bit count.
    public void testPbmac1KeyLengthCapped() throws Exception {
        AlgorithmIdentifier prf = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, null);
        int[] hostile = { 2000, 268435456 };
        for (int i = 0; i != hostile.length; i++)
        {
            AlgorithmIdentifier protectionAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBMAC1,
                new PBMAC1Params(
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params("salt".getBytes(), 1, hostile[i], prf)),
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, null)
                )
            );
            try {
                new JcePBMac1CalculatorProviderBuilder().setProvider(new BouncyCastleProvider())
                    .build().get(protectionAlgorithm, "foobar123".toCharArray());
                fail("PBMAC1 keyLength above the cap should be rejected: " + hostile[i]);
            } catch (OperatorCreationException e) {
                assertTrue(e.getMessage(), e.getMessage().contains("keyLength " + hostile[i] + " greater than 1024"));
            }
        }
    }

    // A PBMAC1 keyLength is attacker-controlled and read before any password/MAC check, so an
    // oversized value must be rejected before the derivation it sizes runs, not after. This version
    // has no lightweight PKCS#12 PBMAC1 builder, so the JCE builder's PBMAC1Params constructor is used.
    public void testPbmac1ParamsKeyLengthBound()
        throws Exception
    {
        PBMAC1Params pbmac1Params = new PBMAC1Params(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2,
                new PBKDF2Params(Strings.toByteArray("saltsalt"), 1, 2000, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256))),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512));

        JcePBMac1CalculatorBuilder builder = new JcePBMac1CalculatorBuilder(pbmac1Params).setProvider(new BouncyCastleProvider());

        try
        {
            builder.build("hello world".toCharArray());
            fail("no exception");
        }
        catch (OperatorCreationException e)
        {
            assertTrue(e.getMessage(), e.getMessage().endsWith("keyLength 2000 greater than 1024"));
        }
    }

    // The PBMAC1 iteration count sits beside the keyLength in the same unauthenticated parameters
    // and drives the PBKDF2 derivation before the MAC can be checked, so the builder has to bound
    // it as well (org.bouncycastle.pbe.max_iteration_count, default 10,000,000).
    public void testPbmac1ParamsIterationCountBound()
        throws Exception
    {
        PBMAC1Params pbmac1Params = new PBMAC1Params(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2,
                new PBKDF2Params(Strings.toByteArray("saltsalt"), Integer.MAX_VALUE, 32, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256))),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256));

        JcePBMac1CalculatorBuilder builder = new JcePBMac1CalculatorBuilder(pbmac1Params).setProvider(new BouncyCastleProvider());

        try
        {
            builder.build("hello world".toCharArray());
            fail("no exception");
        }
        catch (OperatorCreationException e)
        {
            assertTrue(e.getMessage(), e.getMessage().endsWith("iteration count (2147483647) greater than 10000000"));
        }
    }
}
