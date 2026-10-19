/**
 * QMOOSA Zero-Knowledge Cryptography — Groth16 Verification Engine
 *
 * Implements BN254 (alt_bn128) pairing-friendly elliptic curve operations,
 * public input linear combination evaluation, subgroup checks, and Groth16
 * pairing equation verification using the audited @noble/curves library.
 */

import { bn254 } from '@noble/curves/bn254.js';
import {
  BN254_SCALAR_MODULUS_R,
  validateScalarFieldElement,
  type G1Point,
  type G2Point,
  type Groth16Proof,
  type Groth16VerifyingKey
} from '@qmoosa/zk-groth16-protocol';

export * from '@qmoosa/zk-groth16-protocol';

function toG1Projective(pt: G1Point) {
  try {
    const p = bn254.G1.Point.fromAffine({ x: pt.x, y: pt.y });
    p.assertValidity();
    return p;
  } catch (err) {
    throw new Error(`INVALID_G1_POINT: Point not on curve or not in subgroup: ${(err as Error).message}`);
  }
}

function toG2Projective(pt: G2Point) {
  try {
    const p = bn254.G2.Point.fromAffine({
      x: { c0: pt.x[0], c1: pt.x[1] },
      y: { c0: pt.y[0], c1: pt.y[1] }
    });
    p.assertValidity();
    return p;
  } catch (err) {
    throw new Error(`INVALID_G2_POINT: Point not on G2 curve or not in subgroup: ${(err as Error).message}`);
  }
}

function fromG1Affine(p: any): G1Point {
  const aff = p.toAffine();
  return { x: aff.x, y: aff.y };
}

function fromG2Affine(p: any): G2Point {
  const aff = p.toAffine();
  return {
    x: [aff.x.c0, aff.x.c1],
    y: [aff.y.c0, aff.y.c1]
  };
}

export class Groth16Engine {
  /**
   * Verifies a Groth16 proof against a verifying key and public inputs over the BN254 curve.
   *
   * Verification Equation:
   * e(A, B) = e(alpha1, beta2) * e(L, gamma2) * e(C, delta2)
   * where L = IC_0 + sum_{i=1}^l (x_i * IC_i) in G1.
   */
  public verifyProof(
    vk: Groth16VerifyingKey,
    proof: Groth16Proof,
    publicInputs: readonly bigint[]
  ): boolean {
    if (publicInputs.length + 1 !== vk.ic.length) {
      throw new Error(
        `PUBLIC_INPUTS_LENGTH_MISMATCH: Expected ${vk.ic.length - 1} inputs, got ${publicInputs.length}`
      );
    }

    for (const input of publicInputs) {
      validateScalarFieldElement(input);
    }

    // Parse and validate points
    const a = toG1Projective(proof.a);
    const b = toG2Projective(proof.b);
    const c = toG1Projective(proof.c);

    const alpha1 = toG1Projective(vk.alpha1);
    const beta2 = toG2Projective(vk.beta2);
    const gamma2 = toG2Projective(vk.gamma2);
    const delta2 = toG2Projective(vk.delta2);

    // Compute public input linear combination L = IC_0 + sum_{i=0}^{l-1} (x_i * IC_{i+1})
    let L = toG1Projective(vk.ic[0]);
    for (let i = 0; i < publicInputs.length; i++) {
      const icPoint = toG1Projective(vk.ic[i + 1]);
      // Zero contributes the identity; noble's multiply requires a nonzero scalar.
      if (publicInputs[i] !== 0n) {
        L = L.add(icPoint.multiply(publicInputs[i]));
      }
    }

    // Compute pairings in F_p12
    const p1 = bn254.pairing(a, b);
    const p2 = bn254.pairing(alpha1, beta2);
    const p3 = bn254.pairing(L, gamma2);
    const p4 = bn254.pairing(c, delta2);

    // rhs = p2 * p3 * p4
    const rhs = bn254.fields.Fp12.mul(bn254.fields.Fp12.mul(p2, p3), p4);

    return bn254.fields.Fp12.eql(p1, rhs);
  }

  /**
   * Deterministically synthesizes a valid mock Groth16 circuit, verifying key,
   * proof, and public inputs satisfying the BN254 pairing relation.
   */
  public generateMockCircuit(
    numInputs: number = 2,
    inputValues?: readonly bigint[]
  ): {
    vk: Groth16VerifyingKey;
    proof: Groth16Proof;
    publicInputs: bigint[];
  } {
    const G1 = bn254.G1.Point.BASE;
    const G2 = bn254.G2.Point.BASE;
    const r = BN254_SCALAR_MODULUS_R;

    const publicInputs: bigint[] = inputValues
      ? Array.from(inputValues)
      : Array.from({ length: numInputs }, (_, i) => BigInt(i + 1) * 100n + 7n);

    for (const val of publicInputs) {
      validateScalarFieldElement(val);
    }

    // Choose non-zero secret trapdoors for mock setup
    const aScalar = 3n;
    const bScalar = 5n;
    const dScalar = 11n;
    const eScalar = 13n;
    const fScalar = 17n;

    const alpha1 = fromG1Affine(G1.multiply(aScalar));
    const beta2 = fromG2Affine(G2.multiply(bScalar));
    const gamma2 = fromG2Affine(G2.multiply(dScalar));
    const delta2 = fromG2Affine(G2.multiply(fScalar));

    // Linear combination IC generators
    const icScalars: bigint[] = [7n];
    for (let i = 0; i < publicInputs.length; i++) {
      icScalars.push(BigInt(i + 2) * 19n);
    }

    const ic: G1Point[] = icScalars.map(s => fromG1Affine(G1.multiply(s)));

    // Compute mock L scalar = ic[0] + sum(x_i * ic[i+1]) mod r
    let lScalar = icScalars[0];
    for (let i = 0; i < publicInputs.length; i++) {
      lScalar = (lScalar + publicInputs[i] * icScalars[i + 1]) % r;
    }

    // Proof points: A = G1 * 1, C = G1 * eScalar
    const proofA = fromG1Affine(G1);
    const proofC = fromG1Affine(G1.multiply(eScalar));

    // B scalar = (a * b + l * d + e * f) mod r
    const bProofScalar = ((aScalar * bScalar) + (lScalar * dScalar) + (eScalar * fScalar)) % r;
    const proofB = fromG2Affine(G2.multiply(bProofScalar));

    const vk: Groth16VerifyingKey = {
      alpha1,
      beta2,
      gamma2,
      delta2,
      ic
    };

    const proof: Groth16Proof = {
      a: proofA,
      b: proofB,
      c: proofC
    };

    return { vk, proof, publicInputs };
  }
}
