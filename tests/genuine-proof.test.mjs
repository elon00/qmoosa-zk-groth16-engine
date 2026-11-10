import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { Groth16Engine, BN254_SCALAR_MODULUS_R } from '../dist/index.js';

const load = name => JSON.parse(fs.readFileSync(new URL('./fixtures/groth16/' + name, import.meta.url), 'utf8'));
const rawKey = load('verification_key.json');
const g1 = p => ({ x: BigInt(p[0]), y: BigInt(p[1]) });
const g2 = p => ({
  x: [BigInt(p[0][0]), BigInt(p[0][1])],
  y: [BigInt(p[1][0]), BigInt(p[1][1])]
});
const key = {
  alpha1: g1(rawKey.vk_alpha_1), beta2: g2(rawKey.vk_beta_2),
  gamma2: g2(rawKey.vk_gamma_2), delta2: g2(rawKey.vk_delta_2),
  ic: rawKey.IC.map(g1)
};
const proof = raw => ({ a: g1(raw.pi_a), b: g2(raw.pi_b), c: g1(raw.pi_c) });
const normalProof = proof(load('proof.json'));
const normalInputs = load('public.json').map(BigInt);
const zeroProof = proof(load('proof-zero.json'));
const zeroInputs = load('public-zero.json').map(BigInt);
const engine = new Groth16Engine();

test('genuine circuit: accepts the independently verified Groth16 proof', () => {
  assert.equal(rawKey.protocol, 'groth16');
  assert.equal(engine.verifyProof(key, normalProof, normalInputs), true);
});
test('genuine circuit: accepts a valid zero public input', () => {
  assert.ok(zeroInputs.includes(0n), 'Fixture must actually exercise zero');
  assert.equal(engine.verifyProof(key, zeroProof, zeroInputs), true);
});
test('genuine circuit: changed public output is rejected', () => {
  const changed = [...normalInputs];
  changed[0] = (changed[0] + 1n) % BN254_SCALAR_MODULUS_R;
  assert.equal(engine.verifyProof(key, normalProof, changed), false);
});
test('genuine circuit: changed valid proof point is rejected', () => {
  assert.notDeepEqual(normalProof.a, { x: 1n, y: 2n });
  assert.equal(engine.verifyProof(key, { ...normalProof, a: { x: 1n, y: 2n } }, normalInputs), false);
});
test('genuine circuit: malformed proof point is rejected', () => {
  assert.throws(
    () => engine.verifyProof(key, { ...normalProof, a: { x: 999n, y: 999n } }, normalInputs),
    /INVALID_G1_POINT/
  );
});
test('genuine circuit: missing public input is rejected', () => {
  assert.throws(() => engine.verifyProof(key, normalProof, normalInputs.slice(1)), /PUBLIC_INPUTS_LENGTH_MISMATCH/);
});
test('genuine circuit: scalar modulus is rejected rather than reduced', () => {
  const changed = [...normalInputs]; changed[0] = BN254_SCALAR_MODULUS_R;
  assert.throws(() => engine.verifyProof(key, normalProof, changed), /SCALAR_FIELD_OVERFLOW/);
});
test('genuine circuit: negative public input is rejected', () => {
  const changed = [...normalInputs]; changed[0] = -1n;
  assert.throws(() => engine.verifyProof(key, normalProof, changed), /SCALAR_FIELD_OVERFLOW/);
});
