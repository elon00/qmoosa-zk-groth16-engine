import test from 'node:test';
import assert from 'node:assert/strict';
import {
  Groth16Engine,
  BN254_SCALAR_MODULUS_R
} from '../dist/index.js';

test('Groth16 Engine: End-to-End BN254 Pairing Verification on Genuine Proof', () => {
  const engine = new Groth16Engine();
  const { vk, proof, publicInputs } = engine.generateMockCircuit(2, [100n, 200n]);

  const isValid = engine.verifyProof(vk, proof, publicInputs);
  assert.equal(isValid, true, 'Genuine Groth16 proof must verify successfully');
});

test('Groth16 Engine: Multi-Input Circuit Verification (5 Public Inputs)', () => {
  const engine = new Groth16Engine();
  const inputs = [10n, 20n, 30n, 40n, 50n];
  const { vk, proof, publicInputs } = engine.generateMockCircuit(5, inputs);

  const isValid = engine.verifyProof(vk, proof, publicInputs);
  assert.equal(isValid, true, 'Multi-input Groth16 circuit must verify successfully');
});

test('Groth16 Engine: Adversarial Negative Control - Tampered Public Input Rejection', () => {
  const engine = new Groth16Engine();
  const { vk, proof, publicInputs } = engine.generateMockCircuit(2, [100n, 200n]);

  // Adversary alters public input from 100n to 101n
  const tamperedInputs = [101n, 200n];
  const isValid = engine.verifyProof(vk, proof, tamperedInputs);
  assert.equal(isValid, false, 'Tampered public input must fail verification');
});

test('Groth16 Engine: Adversarial Negative Control - Corrupted Proof Point A Rejection', () => {
  const engine = new Groth16Engine();
  const { vk, proof, publicInputs } = engine.generateMockCircuit(2);

  // Substitute proof A with different valid G1 point
  const corruptedProof = {
    ...proof,
    a: vk.alpha1
  };

  const isValid = engine.verifyProof(vk, corruptedProof, publicInputs);
  assert.equal(isValid, false, 'Corrupted proof point A must fail verification');
});

test('Groth16 Engine: Adversarial Negative Control - Corrupted Proof Point B Rejection', () => {
  const engine = new Groth16Engine();
  const { vk, proof, publicInputs } = engine.generateMockCircuit(2);

  // Substitute proof B with vk.beta2
  const corruptedProof = {
    ...proof,
    b: vk.beta2
  };

  const isValid = engine.verifyProof(vk, corruptedProof, publicInputs);
  assert.equal(isValid, false, 'Corrupted proof point B must fail verification');
});

test('Groth16 Engine: Adversarial Negative Control - Corrupted Proof Point C Rejection', () => {
  const engine = new Groth16Engine();
  const { vk, proof, publicInputs } = engine.generateMockCircuit(2);

  // Substitute proof C with different point
  const corruptedProof = {
    ...proof,
    c: vk.ic[0]
  };

  const isValid = engine.verifyProof(vk, corruptedProof, publicInputs);
  assert.equal(isValid, false, 'Corrupted proof point C must fail verification');
});

test('Groth16 Engine: Adversarial Negative Control - Public Inputs Length Mismatch Throws', () => {
  const engine = new Groth16Engine();
  const { vk, proof } = engine.generateMockCircuit(2);

  // Provide 3 inputs instead of 2
  assert.throws(
    () => engine.verifyProof(vk, proof, [100n, 200n, 300n]),
    /PUBLIC_INPUTS_LENGTH_MISMATCH/
  );
});

test('Groth16 Engine: Adversarial Negative Control - Scalar Range Overflow Throws', () => {
  const engine = new Groth16Engine();
  const { vk, proof } = engine.generateMockCircuit(2);

  // Scalar exceeding r
  const overflowScalar = BN254_SCALAR_MODULUS_R + 5n;
  assert.throws(
    () => engine.verifyProof(vk, proof, [overflowScalar, 200n]),
    /SCALAR_FIELD_OVERFLOW/
  );
});

test('Groth16 Engine: Adversarial Negative Control - Non-Curve G1 Point Throws', () => {
  const engine = new Groth16Engine();
  const { vk, proof, publicInputs } = engine.generateMockCircuit(2);

  // Forged point not on curve y^2 != x^3 + 3
  const invalidPointProof = {
    ...proof,
    a: { x: 999n, y: 999n }
  };

  assert.throws(
    () => engine.verifyProof(vk, invalidPointProof, publicInputs),
    /INVALID_G1_POINT/
  );
});
